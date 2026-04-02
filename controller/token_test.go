package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/m-lab/access/token"
)

type fakeVerifier struct {
	claims *jwt.Claims
	err    error
}

func (f *fakeVerifier) Verify(token string, exp jwt.Expected) (*jwt.Claims, error) {
	return f.claims, f.err
}

type fakeIntegrationVerifier struct {
	claims *jwt.Claims
	ic     *token.IntegrationClaims
	err    error
}

func (f *fakeIntegrationVerifier) Verify(tok string, exp jwt.Expected) (*jwt.Claims, error) {
	return f.claims, f.err
}

func (f *fakeIntegrationVerifier) VerifyWithIntegrationClaims(tok string, exp jwt.Expected) (*jwt.Claims, *token.IntegrationClaims, error) {
	return f.claims, f.ic, f.err
}

func TestTokenController_Limit(t *testing.T) {
	tests := []struct {
		name       string
		issuer     string
		machine    string
		verifier   Verifier
		required   bool
		token      string
		code       int
		visited    bool
		monitoring bool
		expected   Paths
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
			expected: Paths{"/": true},
		},
		{
			name:    "success-without-path",
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
			expected: Paths{"/another-path": true},
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
			expected: Paths{"/": true},
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
			expected:   Paths{"/": true},
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
			expected: Paths{"/": true},
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
			expected: Paths{"/": true},
		},
		{
			name:     "error-nil-verifier",
			issuer:   locateIssuer,
			machine:  "mlab1.fake0",
			verifier: (*fakeVerifier)(nil),
			required: true,
			expected: Paths{"/": true},
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
			expected: Paths{"/": true},
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
			expected: Paths{"/": true},
			wantErr:  true,
		},
		{
			name:    "error-nil-paths",
			issuer:  "foo",
			machine: "mlab1.fake0",
			verifier: &fakeVerifier{
				err: fmt.Errorf("fake failure to verify"),
			},
			required: true,
			expected: nil,
			wantErr:  true,
		},
		{
			name:    "success-with-integration-claims",
			issuer:  locateIssuer,
			machine: "mlab1.fake0",
			verifier: &fakeIntegrationVerifier{
				claims: &jwt.Claims{
					Issuer:   locateIssuer,
					Audience: []string{"mlab1.fake0"},
					Expiry:   jwt.NewNumericDate(time.Now()),
				},
				ic: &token.IntegrationClaims{
					IntegrationID: "test-int",
					KeyID:         "ki_test",
				},
			},
			required: true,
			token:    "this-is-a-fake-token",
			code:     http.StatusOK,
			visited:  true,
			expected: Paths{"/": true},
		},
		{
			name:    "success-with-empty-integration-claims",
			issuer:  locateIssuer,
			machine: "mlab1.fake0",
			verifier: &fakeIntegrationVerifier{
				claims: &jwt.Claims{
					Issuer:   locateIssuer,
					Audience: []string{"mlab1.fake0"},
					Expiry:   jwt.NewNumericDate(time.Now()),
				},
				ic: &token.IntegrationClaims{},
			},
			required: true,
			token:    "this-is-a-fake-token",
			code:     http.StatusOK,
			visited:  true,
			expected: Paths{"/": true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exp := jwt.Expected{
				Issuer:      tt.issuer,
				AnyAudience: jwt.Audience{tt.machine},
			}
			tc, err := NewTokenController(tt.verifier, tt.required, exp, tt.expected)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTokenController() returned err; got %v, wantErr %t", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			visited := false
			isMonitoring := false
			var gotIC *token.IntegrationClaims
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				visited = true
				isMonitoring = IsMonitoring(GetClaim(req.Context()))
				gotIC = GetIntegrationClaims(req.Context())
			})
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Form = url.Values{}
			if tt.token != "" {
				req.Form.Set("access_token", tt.token)
			}
			rw := httptest.NewRecorder()

			tc.Limit(next).ServeHTTP(rw, req)

			if rw.Code != tt.code {
				t.Errorf("TokenController.Limit() wrong http code; got %d, want %d", rw.Code, tt.code)
			}
			if visited != tt.visited {
				t.Errorf("TokenController.Limit() wrong visited; got %t, want %t", visited, tt.visited)
			}
			if isMonitoring != tt.monitoring {
				t.Errorf("TokenController.Limit() monitoring is wrong; got %t, want %t", isMonitoring, tt.monitoring)
			}
			if tt.name == "success-with-integration-claims" {
				if gotIC == nil {
					t.Error("Expected integration claims in context, got nil")
				} else {
					if gotIC.IntegrationID != "test-int" {
						t.Errorf("Expected int_id 'test-int', got %q", gotIC.IntegrationID)
					}
					if gotIC.KeyID != "ki_test" {
						t.Errorf("Expected key_id 'ki_test', got %q", gotIC.KeyID)
					}
				}
			}
			if tt.name == "success-with-empty-integration-claims" {
				if gotIC != nil {
					t.Errorf("Expected no integration claims for empty claims, got %+v", gotIC)
				}
			}
		})
	}
}
