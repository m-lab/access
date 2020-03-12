package controller

import (
	"context"
	"testing"

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
		Issuer: monitorIssuer,
	}
	if !IsMonitoring(cl) {
		t.Errorf("IsMonitoring() did not recognize monitoring issuer; got false, want true")
	}
	if IsMonitoring(nil) {
		t.Errorf("IsMonitoring() did not recognize monitoring issuer; got true, want false")
	}
}
