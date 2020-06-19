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
	verifyKeys    = flagx.FileBytesArray{}
	listenAddr    string
	maxIPs        int64
	certFile      string
	keyFile       string
	machine       string
	requireTokens bool
	subject       string
	manageDevice  string
	tcpNetwork    = flagx.Enum{
		Options: []string{"tcp", "tcp4", "tcp6"},
		Value:   "tcp",
	}
)

func init() {
	flag.StringVar(&listenAddr, "envelope.listen-address", ":8880", "Listen address for the envelope access API")
	flag.Int64Var(&maxIPs, "envelope.max-clients", 1, "Maximum number of concurrent client IPs allowed")
	flag.StringVar(&keyFile, "envelope.cert", "", "TLS certificate for envelope server")
	flag.StringVar(&certFile, "envelope.key", "", "TLS key for envelope server")
	flag.Var(&verifyKeys, "envelope.verify-key", "Public key(s) for verifying access tokens")
	flag.BoolVar(&requireTokens, "envelope.token-required", true, "Require access token in requests")
	flag.StringVar(&machine, "envelope.machine", "", "The machine name to expect in access token claims")
	flag.StringVar(&subject, "envelope.subject", "", "The subject (service name) expected in access token claims")
	flag.StringVar(&manageDevice, "envelope.device", "eth0", "The public network interface device name that the envelope manages")
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

	if cl.Subject != env.subject {
		logx.Debug.Println("wrong subject claim")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Tests may run (possibly repeatedly) until the claim expires.
	deadline := cl.Expiry.Time()
	if deadline.Before(time.Now()) {
		logx.Debug.Println("already past expiration")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Use client remote address as the basis of granting temporary subnet access.
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		logx.Debug.Println("failed to split remote addr")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	allow := net.ParseIP(host)
	err = env.Grant(allow)
	switch {
	case err == address.ErrMaxConcurrent:
		logx.Debug.Println("grant limit reached")
		rw.WriteHeader(http.StatusServiceUnavailable)
		return
	case err != nil:
		logx.Debug.Println("grant failed")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithDeadline(req.Context(), deadline)
	defer cancel()
	// Keep the lease until:
	// * client disconnects.
	// * timeout expires.
	// * parent context is cancelled.
	<-ctx.Done()
	// TODO: handle panic.
	rtx.PanicOnError(env.Revoke(allow), "Failed to remove rule for "+allow.String())
}

var mainCtx, mainCancel = context.WithCancel(context.Background())
var getEnvelopeHandler = func(subject string, mgr *address.IPManager) envelopeHandler {
	return envelopeHandler{
		manager: mgr,
		subject: subject,
	}
}

func main() {
	flagx.EnableAdvancedFlags() // Enable access to -httpx.tcp-network
	flag.Parse()
	log.SetFlags(log.LUTC | log.Lshortfile | log.LstdFlags)
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not parse env args")

	prom := prometheusx.MustServeMetrics()
	defer prom.Close()

	verify, err := token.NewVerifier(verifyKeys.Get()...)
	rtx.Must(err, "Failed to create token verifier")

	mgr := address.NewIPManager(maxIPs)
	env := getEnvelopeHandler(subject, mgr)
	ctl, _ := controller.Setup(mainCtx, verify, requireTokens, machine)
	// Handle all requests using the alice http handler chaining library.
	// Start with request logging.
	ac := alice.New(logger).Extend(ctl)
	mux := http.NewServeMux()
	mux.HandleFunc("/v0/envelope/access", env.AllowRequest)
	srv := &http.Server{
		Addr:    listenAddr,
		Handler: ac.Then(mux),
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
