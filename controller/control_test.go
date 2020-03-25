package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/justinas/alice"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestGetClaim(t *testing.T) {
	// Set claim.
	ctx := context.Background()
	cl := &jwt.Claims{}
	ctx = SetClaim(ctx, cl)
	if got := GetClaim(ctx); got == nil || got != cl {
		t.Errorf("Set/GetClaim() wrong; got nil, want %v", cl)
	}

	// Get claim from ctx without a value.
	ctx = context.Background()
	if cl := GetClaim(ctx); cl != nil {
		t.Errorf("Set/GetClaim() wrong; got %v, want nil", cl)
	}

	// Verify that a nil context WAI.
	if cl := GetClaim(nil); cl != nil {
		t.Errorf("Set/GetClaim() wrong; got %v, want nil", cl)
	}
}

func TestIsMonitoring(t *testing.T) {
	cl := &jwt.Claims{
		Issuer:  "locate",
		Subject: monitorSubject,
	}
	if !IsMonitoring(cl) {
		t.Errorf("IsMonitoring() did not recognize monitoring issuer; got false, want true")
	}
	if IsMonitoring(nil) {
		t.Errorf("IsMonitoring() did not recognize monitoring issuer; got true, want false")
	}
}

func TestSetupDefault(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		v        *fakeVerifier
		device   string
		ac       alice.Chain
		tx       *TxController
		wantNil  bool
	}{
		{
			name:    "success-logging-only",
			v:       nil,
			device:  "no-such-device",
			wantNil: true,
		},
		{
			name:     "success-all-controllers",
			hostname: "mlab1.foo01",
			v:        &fakeVerifier{},
			device:   "eth0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			// Use synthetic proc data to allow tests to work on any platform.
			procPath = "testdata/proc-success"
			device = tt.device
			ac, tx := Setup(ctx, tt.v, false, tt.hostname)
			// The tx controller only works in linux; only report errors for linux.
			if (tx != nil) == tt.wantNil {
				t.Errorf("Setup() tx = %v, wantNil %v", tx, tt.wantNil)
				return
			}

			visited := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				visited = true
			})
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rw := httptest.NewRecorder()

			ac.Then(next).ServeHTTP(rw, req)

			if rw.Code != http.StatusOK {
				t.Errorf("Setup() Then() wrong http code; got %d, want %d", rw.Code, http.StatusOK)
			}
			if !visited {
				t.Errorf("Setup() Then() not visited; got false, want true")
			}
		})
	}
}
