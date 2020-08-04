package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/websocket"
	"github.com/justinas/alice"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/m-lab/access/address"
	"github.com/m-lab/access/controller"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/osx"
	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
)

func init() {
	// Disable logging during unit testing.
	log.SetOutput(ioutil.Discard)
}

func Test_main(t *testing.T) {
	// Update flags to use fake version of iptables.
	flag.Set("address.iptables", "../../address/testdata/iptables")
	flag.Set("address.iptables-save", "../../address/testdata/iptables-save")
	flag.Set("address.iptables-restore", "../../address/testdata/iptables-restore")

	// Load fake public verify key.
	insecurePublicTestKey := []byte(`{"use":"sig","kty":"EC","kid":"112","crv":"P-256","alg":"ES256",` +
		`"x":"V0NoRfUZ-fPACALnakvKtTyXJ5JtgAWlWm-0NaDWUOE","y":"RDbGu6RVhgJGKCTuya4_IzZhT1GzlEIA5ZkumEZ35Ag"}`)
	f, err := ioutil.TempFile("", "insecure-key-*")
	rtx.Must(err, "failed to create temp key file")
	f.Write(insecurePublicTestKey)
	f.Close()
	defer os.Remove(f.Name())
	verifyKeys = flagx.FileBytesArray{}
	verifyKeys.Set(f.Name())
	defer osx.MustSetenv("IPTABLES_EXIT", "0")()
	defer osx.MustSetenv("IPTABLES_SAVE_EXIT", "0")()

	// Simulate unencrypted server.
	listenAddr = ":0"
	*prometheusx.ListenAddress = ":0"
	mainCancel()
	main()

	// Simulate tls server.
	mainCtx, mainCancel = context.WithCancel(context.Background())
	certFile = "testdata/insecure-cert.pem"
	keyFile = "testdata/insecure-key.pem"
	requireTokens = false // use NullManager.
	mainCancel()
	main()
}

type fakeManager struct {
	grantErr error
}

func (f *fakeManager) Grant(ip net.IP) error {
	return f.grantErr
}
func (f *fakeManager) Revoke(ip net.IP) error {
	return nil
}

// Test_envelopeHandler_AllowRequest_Errors exercises error paths that cannot be
// reached using the websocket client package directly.
func Test_envelopeHandler_AllowRequest_Errors(t *testing.T) {
	subject := "envelope"
	tests := []struct {
		name            string
		method          string
		remote          string
		code            int
		allowEmptyClaim bool
		claim           *jwt.Claims
		grantErr        error
	}{
		{
			name:   "error-bad-method",
			method: http.MethodPost,
			code:   http.StatusMethodNotAllowed,
		},
		{
			name:   "error-no-claim-found",
			method: http.MethodGet,
			code:   http.StatusBadRequest,
			remote: "127.0.0.2:1234",
		},
		{
			name:            "error-allow-empty-claim",
			method:          http.MethodGet,
			code:            http.StatusBadRequest,
			allowEmptyClaim: true,
			remote:          "127.0.0.2:1234",
		},
		{
			name:   "error-remote-host-corrupt",
			method: http.MethodGet,
			code:   http.StatusBadRequest,
			remote: "thisisnotanip-1234",
		},
		{
			name:   "error-claim-subject-is-invalid",
			method: http.MethodGet,
			code:   http.StatusBadRequest,
			remote: "127.0.0.2:1234",
			claim: &jwt.Claims{
				Issuer:  "locate",
				Subject: "wrong-subject",
			},
		},
		{
			name:   "error-claim-is-already-expired",
			method: http.MethodGet,
			code:   http.StatusBadRequest,
			remote: "127.0.0.2:1234",
			claim: &jwt.Claims{
				Issuer:  "locate",
				Subject: subject,
				Expiry:  jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			},
		},
		{
			name:   "error-grant-ip-failure-max-concurrent",
			method: http.MethodGet,
			code:   http.StatusServiceUnavailable,
			remote: "127.0.0.2:1234",
			claim: &jwt.Claims{
				Issuer:  "locate",
				Subject: subject,
				Expiry:  jwt.NewNumericDate(time.Now().Add(time.Minute)),
			},
			grantErr: address.ErrMaxConcurrent,
		},
		{
			name:   "error-grant-ip-failure-",
			method: http.MethodGet,
			code:   http.StatusInternalServerError,
			remote: "127.0.0.2:1234",
			claim: &jwt.Claims{
				Issuer:  "locate",
				Subject: subject,
				Expiry:  jwt.NewNumericDate(time.Now().Add(time.Minute)),
			},
			grantErr: errors.New("generic grant error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, "/v0/envelope/access", nil)
			env := &envelopeHandler{
				manager: &fakeManager{
					grantErr: tt.grantErr,
				},
				subject: "envelope",
			}
			requireTokens = !tt.allowEmptyClaim
			if tt.claim != nil {
				req = req.Clone(controller.SetClaim(req.Context(), tt.claim))
			}

			req.RemoteAddr = tt.remote
			env.AllowRequest(rw, req)

			if tt.code != rw.Code {
				t.Errorf("AllowRequest() wrong status code; got %d, want %d", rw.Code, tt.code)
			}
		})
	}
}

func Test_envelopeHandler_AllowRequest_Websocket(t *testing.T) {
	subject := "envelope"
	tests := []struct {
		name  string
		code  int
		sleep time.Duration
		claim *jwt.Claims
	}{
		{
			name: "success-exit-fast",
			code: http.StatusSwitchingProtocols,
			claim: &jwt.Claims{
				Issuer:  "locate",
				Subject: subject,
				Expiry:  jwt.NewNumericDate(time.Now().Add(time.Second)),
			},
		},
		{
			name: "success-wait-for-timeout",
			code: http.StatusSwitchingProtocols,
			claim: &jwt.Claims{
				Issuer:  "locate",
				Subject: subject,
				Expiry:  jwt.NewNumericDate(time.Now().Add(time.Second)),
			},
			sleep: 2 * time.Second, // 2x as long as the expiration time.
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := &envelopeHandler{
				manager: &fakeManager{},
				subject: "envelope",
			}
			requireTokens = true

			// Create a synthetic token claim handler that adds the unit test
			// claim to the request context. It is simpler to inject the claim
			// instead of invoking the PKI needed to sign and verify a real claim.
			addClaims := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Unconditionally assign the unit test claim to the request context.
					next.ServeHTTP(w, r.Clone(controller.SetClaim(r.Context(), tt.claim)))
				})
			}
			//
			ac := alice.New(addClaims).Then(http.HandlerFunc(env.AllowRequest))

			mux := http.NewServeMux()
			mux.Handle("/v0/envelope/access", ac)

			srv := httptest.NewServer(mux)
			defer srv.Close()

			headers := http.Header{}
			headers.Add("Sec-WebSocket-Protocol", "net.measurementlab.envelope")
			c, resp, _ := websocket.DefaultDialer.Dial(
				strings.Replace(srv.URL, "http", "ws", 1)+"/v0/envelope/access", headers)
			if tt.code != resp.StatusCode {
				t.Errorf("AllowRequest() wrong status code; got %d, want %d", resp.StatusCode, tt.code)
			}
			if c != nil {
				time.Sleep(tt.sleep)
				c.Close()
			}
		})
	}
}

func Test_customFormat(t *testing.T) {
	tests := []struct {
		name  string
		param handlers.LogFormatterParams
		want  string
	}{
		{
			name: "success",
			param: handlers.LogFormatterParams{
				Request: &http.Request{
					Method:     http.MethodPost,
					Proto:      "HTTP/1.1",
					RemoteAddr: "127.0.0.1:1234",
				},
				TimeStamp: time.Date(2019, time.January, 2, 12, 30, 45, 0, time.UTC),
				URL: url.URL{
					Scheme:   "https",
					Host:     "localhost",
					Path:     "/v0/envelope/access",
					RawQuery: "?this-will-be-removed",
				},
				StatusCode: http.StatusOK,
				Size:       321,
			},
			want: "127.0.0.1:1234 2019-01-02T12:30:45Z HTTP/1.1 POST https://localhost/v0/envelope/access 200 321\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			customFormat(w, tt.param)
			if got := w.String(); got != tt.want {
				t.Errorf("customFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}
