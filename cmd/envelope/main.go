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
	"github.com/justinas/alice"

	"github.com/m-lab/access/address"
	"github.com/m-lab/access/controller"
	"github.com/m-lab/access/token"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/httpx"
	"github.com/m-lab/go/logx"
	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
)

var (
	verifyKey   = flagx.FileBytes{}
	listenAddr  string
	removeAfter time.Duration
	maxIPs      int64
	certFile    string
	keyFile     string
)

func init() {
	flag.StringVar(&listenAddr, "envelope.listen-address", ":8880", "Listen address for the envelope access API")
	flag.DurationVar(&removeAfter, "envelope.timeout-after", time.Minute, "Remove allowed IPs after given duration")
	flag.Int64Var(&maxIPs, "envelope.max-clients", 1, "Maximum number of concurrent client IPs allowed")
	flag.StringVar(&keyFile, "envelope.cert", "", "TLS certificate for envelope server")
	flag.StringVar(&certFile, "envelope.key", "", "TLS key for envelope server")
	flag.Var(&verifyKey, "envelope.verify-key", "Public key for verifying access tokens")
}

type manager interface {
	Grant(ip net.IP) error
	Revoke(ip net.IP) error
}

type envelopeHandler struct {
	manager
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
	// AllowRequest is a state-changing POST method.
	if req.Method != http.MethodPost {
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	cl := controller.GetClaim(req.Context())
	if cl == nil {
		// This could happen if the TokenController is disabled.
		logx.Debug.Println("missing claim")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Use the claim subject as the client IP.
	ip := net.ParseIP(cl.Subject)
	if ip == nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Attempt to grant access for the client IP.
	err := env.Grant(ip)
	switch {
	case err == address.ErrMaxConcurrent:
		rw.WriteHeader(http.StatusServiceUnavailable)
		return
	case err != nil:
		logx.Debug.Println("grant failed")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(req.Context(), removeAfter)
	defer cancel()
	// Keep the lease until:
	// * client disconnects.
	// * timeout expires.
	// * parent context is cancelled.
	<-ctx.Done()
	// TODO: handle panic.
	rtx.PanicOnError(env.Revoke(ip), "Failed to remove rule for "+ip.String())
}

var mainCtx, mainCancel = context.WithCancel(context.Background())
var getEnvelopeHandler = func() envelopeHandler {
	return envelopeHandler{
		manager: address.NewIPManager(maxIPs),
	}
}

func main() {
	flag.Parse()
	log.SetFlags(log.LUTC | log.Lshortfile | log.LstdFlags)

	prom := prometheusx.MustServeMetrics()
	defer prom.Close()

	verify, err := token.NewVerifier(verifyKey)
	rtx.Must(err, "Failed to create token verifier")

	env := getEnvelopeHandler()
	ctl, _ := controller.Setup(mainCtx, verify)
	// Log all requests.
	ac := alice.New(logger).Extend(ctl)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/allow", env.AllowRequest)
	srv := &http.Server{
		Addr:    listenAddr,
		Handler: ac.Then(mux),
	}
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
