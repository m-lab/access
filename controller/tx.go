package controller

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/procfs"
)

var (
	procPath         = "/proc"
	device           string
	maxRate          uint64
	txAccessRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "controller_access_txcontroller_requests_total",
			Help: "Total number of requests handled by the access txcontroller.",
		},
		[]string{"request", "protocol"},
	)
	// ErrNoDevice is returned when device is empty or not found in procfs.
	ErrNoDevice = errors.New("no device found")

	// ErrNilPaths is returned when a nil Paths value is given.
	ErrNilPaths = errors.New("nil paths value given")
)

func init() {
	flag.StringVar(&device, "txcontroller.device", "", "Calculate bytes transmitted from this device.")
	flag.Uint64Var(&maxRate, "txcontroller.max-rate", 0, "The max rate (in bit/s) beyond which, the TxController will reject new clients")
}

// TxController calculates the bytes transmitted every period from the named device.
type TxController struct {
	period  time.Duration
	device  string
	current uint64
	limit   uint64
	pfs     procfs.FS

	// Enforced is a set of HTTP request resource paths on which the
	// TokenController will enforce token authorization. Any resource missing
	// from the Enforced set, is allowed. When the TxController is used for
	// Accept(), these paths have no effect.
	Enforced Paths
}

// NewTxController creates a new instance and runs TxController.Watch in a
// goroutine to observe the current rate every 100 msec. When the given context
// is canceled or expires, Watch will return and the TxController will no longer
// be updated until Watch is started again.
func NewTxController(ctx context.Context, enforced Paths) (*TxController, error) {
	if enforced == nil {
		return nil, ErrNilPaths
	}
	if device == "" {
		return nil, ErrNoDevice
	}
	pfs, err := procfs.NewFS(procPath)
	if err != nil {
		return nil, err
	}
	// Read the device once to verify that the device exists.
	_, err = readNetDevLine(pfs, device)
	if err != nil {
		return nil, err
	}
	tx := &TxController{
		device:   device,
		limit:    maxRate,
		pfs:      pfs,
		period:   100 * time.Millisecond,
		Enforced: enforced,
	}
	// Run watch in a goroutine.
	go tx.Watch(ctx)
	return tx, nil
}

// Accept wraps the call to listener's Accept. If the TxController is
// limited, then Accept immediately closes the connection and returns an error.
func (tx *TxController) Accept(l net.Listener) (net.Conn, error) {
	conn, err := l.Accept()
	if tx == nil {
		// Simple pass-through.
		return conn, err
	}
	if err != nil {
		// No need to check isLimited, the accept failed.
		return nil, err
	}
	// NOTE: treat all raw accept requests as an "enforced path".
	if tx.isLimited("raw", false, true) {
		defer conn.Close()
		return nil, fmt.Errorf("TxController rejected connection %s", conn.RemoteAddr())
	}
	// err was nil, so the conn is good.
	return conn, nil
}

// Current exports the current rate. Useful for diagnostics.
func (tx *TxController) Current() uint64 {
	return atomic.LoadUint64(&tx.current)
}
func (tx *TxController) set(value uint64) {
	atomic.StoreUint64(&tx.current, value)
}

// isLimited checks the current tx rate and returns whether the connection
// should be accepted or rejected. If monitoring is true, then even if the
// current limit is exceeded, the request will be accepted.
func (tx *TxController) isLimited(proto string, monitoring, enforcedPath bool) bool {
	cur := tx.Current()
	if tx.limit > 0 && cur > tx.limit && !monitoring && enforcedPath {
		txAccessRequests.WithLabelValues("rejected", proto).Inc()
		return true
	}
	txAccessRequests.WithLabelValues("accepted", proto).Inc()
	return false
}

// Limit enforces that the TxController rate limit is respected before running
// the next handler. If the rate is unspecified (zero), all requests are accepted.
func (tx *TxController) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Discover whether the access token was issued for monitoring.
		monitoring := IsMonitoring(GetClaim(r.Context()))
		if tx.isLimited("http", monitoring, tx.Enforced[r.URL.Path]) {
			// 503 - https://tools.ietf.org/html/rfc7231#section-6.6.4
			w.WriteHeader(http.StatusServiceUnavailable)
			// Return without additional response.
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Watch updates the current rate every period. If the context is cancelled, the
// context error is returned. If the TxController rate is zero, Watch returns
// immediately. Callers should typically run Watch in a goroutine.
func (tx *TxController) Watch(ctx context.Context) error {
	if tx.limit == 0 {
		// No need to do anything.
		return nil
	}
	t := time.NewTicker(tx.period)
	defer t.Stop()

	// Read current vaule of TxBytes for device to initialize the following loop.
	v, err := readNetDevLine(tx.pfs, tx.device)
	if err != nil {
		return err
	}

	// Setup.
	ratePrev := 0.0
	prevTxBytes := v.TxBytes
	tickNow := <-t.C                    // Read first time from ticker.
	tickPrev := tickNow.Add(-tx.period) // Initialize difference to expected sample period.
	alpha := tx.period.Seconds() / 2    // Alpha controls the decay rate based on configured period.

	// Check the device every period until the context returns an error.
	for ; ctx.Err() == nil; tickNow = <-t.C {
		cur, err := readNetDevLine(tx.pfs, tx.device)
		if err != nil {
			log.Println("Error reading /proc/net/dev:", err)
			continue
		}

		// Under heavy load, tickers may fire slow (and then early). Only update
		// values when interval is long enough, i.e. more than half the tx.period.
		if tickNow.Sub(tickPrev).Seconds() > tx.period.Seconds()/2 {
			// Calculate the new rate in bits-per-second, using the actual interval.
			rateNow := float64(8*(cur.TxBytes-prevTxBytes)) / tickNow.Sub(tickPrev).Seconds()
			// A few seconds for decreases and rapid response for increases.
			ratePrev = math.Max(rateNow, (1-alpha)*ratePrev+alpha*rateNow)
			tx.set(uint64(ratePrev))

			// Save the total bytes sent from this round for the next.
			prevTxBytes = cur.TxBytes
			tickPrev = tickNow
		}
	}
	return ctx.Err()
}

func readNetDevLine(pfs procfs.FS, device string) (procfs.NetDevLine, error) {
	nd, err := pfs.NetDev()
	if err != nil {
		return procfs.NetDevLine{}, err
	}
	// Check at creation time whether device exists.
	v, ok := nd[device]
	if !ok {
		return procfs.NetDevLine{}, fmt.Errorf("Given device not found: %q", device)
	}
	return v, nil
}
