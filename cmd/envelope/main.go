package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/websocket"
	"github.com/justinas/alice"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/m-lab/access/address"
	"github.com/m-lab/access/chanio"
	"github.com/m-lab/access/controller"
	"github.com/m-lab/access/token"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/httpx"
	"github.com/m-lab/go/logx"
	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
)

var (
	verifyKeys    = flagx.FileBytesArray{}
	listenAddr    string
	maxIPs        int64
	certFile      string
	keyFile       string
	machine       string
	requireTokens bool
	subject       string
	manageDevice  string
	timeout       time.Duration
	tcpNetwork    = flagx.Enum{
		Options: []string{"tcp", "tcp4", "tcp6"},
		Value:   "tcp",
	}

	// count the number of requests received and their apparent success or failure.
	envelopeRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "envelope_requests_total",
			Help: "Total number of requests handled by the access envelope.",
		},
		[]string{"status"},
	)
)

func init() {
	flag.StringVar(&listenAddr, "envelope.listen-address", ":8880", "Listen address for the envelope access API")
	flag.Int64Var(&maxIPs, "envelope.max-clients", 1, "Maximum number of concurrent client IPs allowed")
	flag.StringVar(&certFile, "envelope.cert", "", "TLS certificate for envelope server")
	flag.StringVar(&keyFile, "envelope.key", "", "TLS key for envelope server")
	flag.Var(&verifyKeys, "envelope.verify-key", "Public key(s) for verifying access tokens")
	flag.BoolVar(&requireTokens, "envelope.token-required", true, "Require access token in requests")
	flag.StringVar(&machine, "envelope.machine", "", "The machine name to expect in access token claims")
	flag.StringVar(&subject, "envelope.subject", "", "The subject (service name) expected in access token claims")
	flag.StringVar(&manageDevice, "envelope.device", "eth0", "The public network interface device name that the envelope manages")
	flag.DurationVar(&timeout, "timeout", time.Minute, "Complete request within timeout. Overrides valid token expiration")
	flagx.EnableAdvancedFlags() // Enable access to -httpx.tcp-network
}

type manager interface {
	Grant(ip net.IP) error
	Revoke(ip net.IP) error
}

type envelopeHandler struct {
	manager
	subject string
}

func logger(next http.Handler) http.Handler {
	return handlers.CustomLoggingHandler(os.Stderr, next, customFormat)
}

func customFormat(w io.Writer, p handlers.LogFormatterParams) {
	// Remove the RawQuery to print less unnecessary information.
	p.URL.RawQuery = ""
	fmt.Fprintln(w,
		p.Request.RemoteAddr,
		p.TimeStamp.Format(time.RFC3339Nano),
		p.Request.Proto,
		p.Request.Method,
		p.URL.String(),
		p.StatusCode,
		p.Size,
	)
}

func (env *envelopeHandler) AllowRequest(rw http.ResponseWriter, req *http.Request) {
	// Websocket requests must be GET. Also note that AllowRequest is a
	// state-changing operation.
	if req.Method != http.MethodGet {
		rw.WriteHeader(http.StatusMethodNotAllowed)
		envelopeRequests.WithLabelValues("wrong-method").Inc()
		return
	}

	// Use client remote address as the basis of granting temporary subnet access.
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		logx.Debug.Println("failed to split remote addr:", err)
		rw.WriteHeader(http.StatusBadRequest)
		envelopeRequests.WithLabelValues("bad-remoteaddr").Inc()
		return
	}

	// Get deadline based on token claim.
	cl := controller.GetClaim(req.Context())
	deadline, err := env.getDeadline(cl)
	if err != nil {
		logx.Debug.Println("failed to get deadline:", err)
		rw.WriteHeader(http.StatusBadRequest)
		// NOTE: all errors returned by getDeadline are static strings, so using
		// this as a label should be safe.
		envelopeRequests.WithLabelValues(err.Error()).Inc()
		return
	}

	remote := net.ParseIP(host)
	err = env.Grant(remote)
	switch {
	case err == address.ErrMaxConcurrent:
		logx.Debug.Println("grant limit reached")
		rw.WriteHeader(http.StatusServiceUnavailable)
		envelopeRequests.WithLabelValues(address.ErrMaxConcurrent.Error()).Inc()
		return
	case err != nil:
		logx.Debug.Println("grant failed")
		rw.WriteHeader(http.StatusInternalServerError)
		envelopeRequests.WithLabelValues("iptables-grant-failure").Inc()
		return
	}

	conn := setupConn(rw, req)
	if conn == nil {
		logx.Debug.Println("setup websocket conn failed")
		rw.WriteHeader(http.StatusInternalServerError)
		// TODO: handle panic. On panic, process will currently exit.
		rtx.PanicOnError(env.Revoke(remote), "Failed to remove rule for "+remote.String())
		envelopeRequests.WithLabelValues("websocket-setup-failure").Inc()
		return
	}

	// At this point, we want to wait for either the deadline (when the envelope
	// service closes the connection) or the client to close the websocket conn
	// (to signal completion).
	env.wait(req.Context(), conn, deadline)

	// TODO: handle panic. On panic, process will currently exit.
	rtx.PanicOnError(env.Revoke(remote), "Failed to remove rule for "+remote.String())
	envelopeRequests.WithLabelValues("success").Inc()
}

func (env *envelopeHandler) getDeadline(cl *jwt.Claims) (time.Time, error) {
	if cl == nil && requireTokens {
		logx.Debug.Println("missing claim")
		return time.Time{}, fmt.Errorf("missing claim when tokens required")
	}

	// Calculate the earliest the deadline could be.
	minDeadline := time.Now().Add(timeout)

	if cl == nil {
		// This could happen if tokens are not required.
		return minDeadline, nil
	}

	if cl.Subject != env.subject {
		logx.Debug.Println("wrong subject claim")
		return time.Time{}, fmt.Errorf("wrong claim subject")
	}

	// Tests may run (possibly repeatedly) until the claim expires.
	deadline := cl.Expiry.Time()
	if deadline.Before(time.Now()) {
		logx.Debug.Println("already past expiration")
		return time.Time{}, fmt.Errorf("already past claim expiration")
	}

	// If the token deadline is even earlier than the minDeadline, reset to the
	// later time.
	if deadline.Before(minDeadline) {
		deadline = minDeadline
	}
	return deadline, nil
}

func setupConn(writer http.ResponseWriter, request *http.Request) *websocket.Conn {
	headers := http.Header{}
	headers.Add("Sec-WebSocket-Protocol", "net.measurementlab.envelope")
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			// Allow cross origin resource sharing
			return true
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	conn, err := upgrader.Upgrade(writer, request, headers)
	if err != nil {
		logx.Debug.Println("failed to upgrade", err)
		return nil
	}
	return conn
}

func (env *envelopeHandler) wait(ctx context.Context, c *websocket.Conn, dl time.Time) {
	// NOTE: we are explicitly ignoring the error value from SetDeadline.
	// Any error there will show up on read below.
	c.SetReadDeadline(dl)
	c.SetWriteDeadline(dl)
	ctxdl, cancel := context.WithDeadline(ctx, dl)
	defer cancel()
	// Clean up client connection upon return.
	defer c.Close()

	// Keep the client connection open and the IP grant enabled until:
	// * parent context expires.
	// * context deadline expires.
	// * client disconnects (or writes data that we don't expect).
	select {
	case <-ctxdl.Done():
	case <-chanio.ReadOnce(c.UnderlyingConn()):
	}
}

var mainCtx, mainCancel = context.WithCancel(context.Background())
var getEnvelopeHandler = func(subject string, mgr address.Manager) envelopeHandler {
	return envelopeHandler{
		manager: mgr,
		subject: subject,
	}
}

func main() {
	flag.Parse()
	log.SetFlags(log.LUTC | log.Lshortfile | log.LstdFlags)
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not parse env args")

	prom := prometheusx.MustServeMetrics()
	defer prom.Close()

	verify, err := token.NewVerifier(verifyKeys.Get()...)
	rtx.Must(err, "Failed to create token verifier")

	var mgr address.Manager
	if requireTokens {
		mgr = address.NewIPManager(maxIPs)
	} else {
		mgr = &address.NullManager{}
	}
	env := getEnvelopeHandler(subject, mgr)
	ctl, _ := controller.Setup(mainCtx, verify, requireTokens, machine)
	// Handle all requests using the alice http handler chaining library.
	// Start with request logging.
	ac := alice.New(logger).Extend(ctl)
	mux := http.NewServeMux()
	mux.HandleFunc("/v0/envelope/access", env.AllowRequest)
	controller.AllowPathLabel("/v0/envelope/access")
	srv := &http.Server{
		Addr:    listenAddr,
		Handler: ac.Then(mux),

		// NOTE: prevent connections from staying open indefinitely.
		// And, these timeouts are reset for individual clients that
		// negotiate the websocket connection.
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
	}
	_, port, err := net.SplitHostPort(listenAddr)
	rtx.Must(err, "failed to split listen address: %q", listenAddr)
	err = mgr.Start(port, manageDevice)
	rtx.Must(err, "failed to setup iptables management of %q", manageDevice)
	defer mgr.Stop()

	if certFile != "" && keyFile != "" {
		log.Println("Listening for secure access requests on " + listenAddr)
		rtx.Must(httpx.ListenAndServeTLSAsync(srv, certFile, keyFile), "Could not start envelop server")
	} else {
		log.Println("Listening for INSECURE access requests on " + listenAddr)
		rtx.Must(httpx.ListenAndServeAsync(srv), "Could not start envelop server")
	}
	defer srv.Close()
	<-mainCtx.Done()
}
