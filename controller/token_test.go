package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
)

type fakeVerifier struct {
	claims *jwt.Claims
	err    error
}

func (f *fakeVerifier) Verify(token string, exp jwt.Expected) (*jwt.Claims, error) {
	return f.claims, f.err
}

func TestTokenController_Limit(t *testing.T) {
	tests := []struct {
		name       string
		issuer     string
		machine    string
		verifier   *fakeVerifier
		required   bool
		token      string
		code       int
		visited    bool
		monitoring bool
		wantErr    bool
	}{
		{
			name:    "success-without-token",
			issuer:  locateIssuer,
			machine: "mlab1.fake0",
			verifier: &fakeVerifier{
				claims: &jwt.Claims{
					Issuer:   locateIssuer,
					Audience: []string{"mlab1.fake0"},
					Expiry:   jwt.NewNumericDate(time.Now()),
				},
			},
			required: false,
			code:     http.StatusOK,
			visited:  true,
		},
		{
			name:    "success-with-token",
			issuer:  locateIssuer,
			machine: "mlab1.fake0",
			verifier: &fakeVerifier{
				claims: &jwt.Claims{
					Issuer:   locateIssuer,
					Audience: []string{"mlab1.fake0"},
					Expiry:   jwt.NewNumericDate(time.Now()),
				},
			},
			required: false,
			token:    "this-is-a-fake-token",
			code:     http.StatusOK,
			visited:  true,
		},
		{
			name:    "success-with-token-with-monitoring-issuer",
			issuer:  locateIssuer,
			machine: "mlab1.fake0",
			verifier: &fakeVerifier{
				claims: &jwt.Claims{
					Issuer:   locateIssuer,
					Subject:  monitorSubject,
					Audience: []string{"mlab1.fake0"},
					Expiry:   jwt.NewNumericDate(time.Now()),
				},
			},
			required:   true,
			token:      "this-is-a-fake-token",
			code:       http.StatusOK,
			visited:    true,
			monitoring: true, // because the Subject == monitorSubject.
		},
		{
			name:    "error-token-required-but-not-provided",
			issuer:  locateIssuer,
			machine: "mlab1.fake0",
			verifier: &fakeVerifier{
				err: fmt.Errorf("fake failure to verify"),
			},
			required: true,
			token:    "",
			code:     http.StatusUnauthorized,
			visited:  false, // "next" handler is never visited.
		},
		{
			name:    "error-failure-to-verify",
			issuer:  locateIssuer,
			machine: "mlab1.fake0",
			verifier: &fakeVerifier{
				err: fmt.Errorf("fake failure to verify"),
			},
			required: true,
			token:    "this-is-a-fake-token",
			code:     http.StatusUnauthorized,
			visited:  false, // "next" handler is never visited.
		},
		{
			name:     "error-nil-verifier",
			issuer:   locateIssuer,
			machine:  "mlab1.fake0",
			verifier: nil,
			required: true,
			wantErr:  true,
		},
		{
			name:    "error-empty-machine",
			issuer:  locateIssuer,
			machine: "",
			verifier: &fakeVerifier{
				err: fmt.Errorf("fake failure to verify"),
			},
			required: true,
			wantErr:  true,
		},
		{
			name:    "error-empty-issuer",
			issuer:  "",
			machine: "mlab1.fake0",
			verifier: &fakeVerifier{
				err: fmt.Errorf("fake failure to verify"),
			},
			required: true,
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exp := jwt.Expected{
				Issuer:   tt.issuer,
				Audience: jwt.Audience{tt.machine},
			}
			token, err := NewTokenController(tt.verifier, tt.required, exp)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTokenController() returned err; got %v, wantErr %t", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			visited := false
			isMonitoring := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				visited = true
				isMonitoring = IsMonitoring(GetClaim(req.Context()))
			})
			AllowPathLabel("/")
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Form = url.Values{}
			if tt.token != "" {
				req.Form.Set("access_token", tt.token)
			}
			rw := httptest.NewRecorder()

			token.Limit(next).ServeHTTP(rw, req)

			if rw.Code != tt.code {
				t.Errorf("TokenController.Limit() wrong http code; got %d, want %d", rw.Code, tt.code)
			}
			if visited != tt.visited {
				t.Errorf("TokenController.Limit() wrong visited; got %t, want %t", visited, tt.visited)
			}
			if isMonitoring != tt.monitoring {
				t.Errorf("TokenController.Limit() monitoring is wrong; got %t, want %t", isMonitoring, tt.monitoring)
			}
		})
	}
}
