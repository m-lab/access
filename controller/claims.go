package controller

import "context"

// IntegrationClaims contains M-Lab integration-specific JWT claims.
// These identify which integrator and API key were used for a request.
type IntegrationClaims struct {
	IntegrationID string `json:"int_id,omitempty"`
	KeyID         string `json:"key_id,omitempty"`
}

type integrationClaimsContextKeyType struct{}

var integrationClaimsContextKey = integrationClaimsContextKeyType{}

// SetIntegrationClaims returns a derived context with the given integration claims.
func SetIntegrationClaims(ctx context.Context, ic *IntegrationClaims) context.Context {
	return context.WithValue(ctx, integrationClaimsContextKey, ic)
}

// GetIntegrationClaims extracts integration claims from the given context.
// Returns nil if no integration claims are present.
func GetIntegrationClaims(ctx context.Context) *IntegrationClaims {
	if ctx == nil {
		return nil
	}
	value := ctx.Value(integrationClaimsContextKey)
	if value == nil {
		return nil
	}
	return value.(*IntegrationClaims)
}
