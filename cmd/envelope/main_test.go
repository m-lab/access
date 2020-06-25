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
	"testing"
	"time"

	"github.com/gorilla/handlers"
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

func Test_envelopeHandler_AllowRequest(t *testing.T) {
	subject := "envelope"
	tests := []struct {
		name     string
		param    string
		method   string
		remote   string
		code     int
		claim    *jwt.Claims
		grantErr error
	}{
		{
			name:   "error-bad-method",
			method: http.MethodGet,
			code:   http.StatusMethodNotAllowed,
		},
		{
			name:   "error-no-claim-found",
			method: http.MethodPost,
			code:   http.StatusInternalServerError,
		},
		{
			name:   "error-claim-subject-is-invalid",
			method: http.MethodPost,
			code:   http.StatusBadRequest,
			claim: &jwt.Claims{
				Issuer:  "locate",
				Subject: "wrong-subject",
			},
		},
		{
			name:   "error-claim-is-already-expired",
			method: http.MethodPost,
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
			method: http.MethodPost,
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
			name:   "error-split-host-port-failure",
			method: http.MethodPost,
			code:   http.StatusBadRequest,
			remote: "corrupt-remote-ip",
			claim: &jwt.Claims{
				Issuer:  "locate",
				Subject: subject,
				Expiry:  jwt.NewNumericDate(time.Now().Add(time.Minute)),
			},
			grantErr: address.ErrMaxConcurrent,
		},
		{
			name:   "error-grant-ip-failure-",
			method: http.MethodPost,
			code:   http.StatusInternalServerError,
			remote: "127.0.0.2:1234",
			claim: &jwt.Claims{
				Issuer:  "locate",
				Subject: subject,
				Expiry:  jwt.NewNumericDate(time.Now().Add(time.Minute)),
			},
			grantErr: errors.New("generic grant error"),
		},
		{
			name:   "success",
			method: http.MethodPost,
			code:   http.StatusOK,
			remote: "127.0.0.2:1234",
			claim: &jwt.Claims{
				Issuer:  "locate",
				Subject: subject,
				Expiry:  jwt.NewNumericDate(time.Now().Add(time.Second)),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, "/v0/envelope/access"+tt.param, nil)
			env := &envelopeHandler{
				manager: &fakeManager{
					grantErr: tt.grantErr,
				},
				subject: "envelope",
			}
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
