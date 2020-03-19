package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/handlers"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/m-lab/access/address"
	"github.com/m-lab/access/controller"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/prometheusx"
)

func Test_main(t *testing.T) {
	insecurePublicTestKey := `{"use":"sig","kty":"EC","kid":"112","crv":"P-256","alg":"ES256",` +
		`"x":"V0NoRfUZ-fPACALnakvKtTyXJ5JtgAWlWm-0NaDWUOE","y":"RDbGu6RVhgJGKCTuya4_IzZhT1GzlEIA5ZkumEZ35Ag"}`
	listenAddr = ":0"
	*prometheusx.ListenAddress = ":0"
	verifyKey = flagx.FileBytes(insecurePublicTestKey)
	// Simulate unencrypted server.
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
	tests := []struct {
		name     string
		param    string
		method   string
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
			name:   "error-claim-subject-is-invalid-ip",
			method: http.MethodPost,
			code:   http.StatusBadRequest,
			claim: &jwt.Claims{
				Issuer:  "locate",
				Subject: "this-is-an-invalid-ip",
			},
		},
		{
			name:   "error-grant-ip-failure-max-concurrent",
			method: http.MethodPost,
			code:   http.StatusServiceUnavailable,
			claim: &jwt.Claims{
				Issuer:  "locate",
				Subject: "127.0.0.2",
			},
			grantErr: address.ErrMaxConcurrent,
		},
		{
			name:   "error-grant-ip-failure-",
			method: http.MethodPost,
			code:   http.StatusInternalServerError,
			claim: &jwt.Claims{
				Issuer:  "locate",
				Subject: "127.0.0.2",
			},
			grantErr: errors.New("generic grant error"),
		},
		{
			name:   "success",
			method: http.MethodPost,
			code:   http.StatusOK,
			claim: &jwt.Claims{
				Issuer:  "locate",
				Subject: "127.0.0.2",
			},
		},
	}
	for _, tt := range tests {
		//
		removeAfter = time.Millisecond
		t.Run(tt.name, func(t *testing.T) {
			rw := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, "/v0/allow"+tt.param, nil)
			env := &envelopeHandler{
				manager: &fakeManager{
					grantErr: tt.grantErr,
				},
			}
			if tt.claim != nil {
				req = req.Clone(controller.SetClaim(req.Context(), tt.claim))
			}
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
					Path:     "/v0/allow",
					RawQuery: "?this-will-be-removed",
				},
				StatusCode: http.StatusOK,
				Size:       321,
			},
			want: "127.0.0.1:1234 2019-01-02T12:30:45Z HTTP/1.1 POST https://localhost/v0/allow 200 321\n",
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
