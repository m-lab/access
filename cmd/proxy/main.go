// Create a forwarding NewSingleHostReverseProxy for local services that
// supports admission control, including access token validation and utilization
// based "tx controller".
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/handlers"

	"github.com/m-lab/access/controller"
	"github.com/m-lab/access/token"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/httpx"
	"github.com/m-lab/go/rtx"
)

var (
	tokenVerifyKey = flagx.FileBytesArray{}
	tokenRequired  bool
	tokenMachine   string
	certFile       string
	keyFile        string
	forward        = forwardURLs{}
)

type ForwardURL struct {
	From   *url.URL
	Target *url.URL
}

type forwardURLs []ForwardURL

func (f forwardURLs) String() string {
	s := ""
	for i := range f {
		s += f[i].From.String() + "@" + f[i].Target.String()
	}
	return s
}

func (f *forwardURLs) Get() string {
	return f.String()
}

func (f *forwardURLs) Set(s string) error {
	fields := strings.Split(s, "@")
	if len(fields) != 2 {
		return errors.New("from-url@target-url")
	}
	from, err := url.Parse(fields[0])
	if err != nil {
		return err
	}
	target, err := url.Parse(fields[1])
	if err != nil {
		return err
	}
	x := ForwardURL{
		From:   from,
		Target: target,
	}
	*f = append(*f, x)
	return nil
}

func init() {
	flag.Var(&forward, "forward", "listen on from and forward to target url")
	flag.Var(&tokenVerifyKey, "token.verify-key", "Public key for verifying access tokens")
	flag.BoolVar(&tokenRequired, "token.required", false, "Require access token for requests")
	flag.StringVar(&tokenMachine, "token.machine", "", "Use given machine name to verify token claims")
	flag.StringVar(&certFile, "cert", "", "TLS certificate for envelope server")
	flag.StringVar(&keyFile, "key", "", "TLS key for envelope server")
}

var mainCtx, mainCancel = context.WithCancel(context.Background())

func main() {
	defer mainCancel()
	flag.Parse()

	v, err := token.NewVerifier(tokenVerifyKey.Get()...)
	if tokenRequired && err != nil {
		rtx.Must(err, "Failed to load verifier for when tokens are required")
	}
	ac, _ := controller.Setup(mainCtx, v, tokenRequired, tokenMachine)

	for i := range forward {
		rp := httputil.NewSingleHostReverseProxy(forward[i].Target)
		rp.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		h := handlers.LoggingHandler(os.Stderr, rp)
		// h := handlers.CustomLoggingHandler(os.Stderr, rp, LogFormatter)
		smx := http.NewServeMux()
		smx.Handle("/", ac.Then(h))

		listenAddr := forward[i].From.Host
		s := &http.Server{
			Addr:    listenAddr,
			Handler: smx,
			// NOTE: set absolute read and write timeouts for server connections.
			ReadTimeout:  time.Minute, // TODO: make configurable.
			WriteTimeout: time.Minute, // TODO: make configurable.
		}

		switch forward[i].From.Scheme {
		case "https":
			log.Println("Listening for secure access requests on " + listenAddr + " to " + forward[i].Target.String())
			rtx.Must(httpx.ListenAndServeTLSAsync(s, certFile, keyFile), "Could not start envelop server")
		case "http":
			log.Println("Listening for INSECURE access requests on " + listenAddr + " to " + forward[i].Target.String())
			rtx.Must(httpx.ListenAndServeAsync(s), "Could not start envelop server")
		default:
			panic("unknown forward scheme")
		}
		defer s.Close()
	}
	<-mainCtx.Done()
}
