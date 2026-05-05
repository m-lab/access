package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/go-test/deep"
)

// testCustomClaims is a sample caller-defined claim type used to exercise the
// generic NewCustomClaim/SetCustomClaim/GetCustomClaim machinery.
type testCustomClaims struct {
	Foo string
	Bar string
}

type fakeVerifier struct {
	claims *jwt.Claims
	custom *testCustomClaims // if non-nil, populates extra dest
	err    error
}

func (f *fakeVerifier) Verify(tok string, exp jwt.Expected, extraDest ...any) (*jwt.Claims, error) {
	if f.custom != nil {
		for _, d := range extraDest {
			if c, ok := d.(*testCustomClaims); ok {
				*c = *f.custom
			}
		}
	}
	return f.claims, f.err
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
		newCustom  func() any
		wantCustom any
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
			name:    "success-with-custom-claim",
			issuer:  locateIssuer,
			machine: "mlab1.fake0",
			verifier: &fakeVerifier{
				claims: &jwt.Claims{
					Issuer:   locateIssuer,
					Audience: []string{"mlab1.fake0"},
					Expiry:   jwt.NewNumericDate(time.Now()),
				},
				custom: &testCustomClaims{Foo: "f", Bar: "b"},
			},
			required:   true,
			token:      "this-is-a-fake-token",
			code:       http.StatusOK,
			visited:    true,
			expected:   Paths{"/": true},
			newCustom:  func() any { return &testCustomClaims{} },
			wantCustom: &testCustomClaims{Foo: "f", Bar: "b"},
		},
		{
			name:    "success-with-zero-custom-claim",
			issuer:  locateIssuer,
			machine: "mlab1.fake0",
			verifier: &fakeVerifier{
				claims: &jwt.Claims{
					Issuer:   locateIssuer,
					Audience: []string{"mlab1.fake0"},
					Expiry:   jwt.NewNumericDate(time.Now()),
				},
			},
			required:   true,
			token:      "this-is-a-fake-token",
			code:       http.StatusOK,
			visited:    true,
			expected:   Paths{"/": true},
			newCustom:  func() any { return &testCustomClaims{} },
			wantCustom: &testCustomClaims{},
		},
		{
			// NewCustomClaim returning nil must be tolerated and must NOT
			// cause the request to be rejected (no extra dest is sent to
			// Verify, and no value is attached to the context).
			name:    "success-with-nil-custom-claim",
			issuer:  locateIssuer,
			machine: "mlab1.fake0",
			verifier: &fakeVerifier{
				claims: &jwt.Claims{
					Issuer:   locateIssuer,
					Audience: []string{"mlab1.fake0"},
					Expiry:   jwt.NewNumericDate(time.Now()),
				},
			},
			required:   true,
			token:      "this-is-a-fake-token",
			code:       http.StatusOK,
			visited:    true,
			expected:   Paths{"/": true},
			newCustom:  func() any { return nil },
			wantCustom: nil,
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
			tc.NewCustomClaim = tt.newCustom

			visited := false
			isMonitoring := false
			var gotCustom any
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				visited = true
				isMonitoring = IsMonitoring(GetClaim(req.Context()))
				gotCustom = GetCustomClaim(req.Context())
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
			if diff := deep.Equal(gotCustom, tt.wantCustom); diff != nil {
				t.Errorf("TokenController.Limit() custom claim mismatch: %v", diff)
			}
		})
	}
}
