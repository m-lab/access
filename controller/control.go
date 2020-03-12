// Package controller provides various access controllers for use in
// socket-based and HTTP-based services.
package controller

import (
	"context"
	"net/http"

	"gopkg.in/square/go-jose.v2/jwt"
)

// Controller is the interface that all access control types should implement.
type Controller interface {
	Limit(next http.Handler) http.Handler
}

type claimContextIDType struct{}

var claimContextIDKey = claimContextIDType{}

// SetClaim returns a derived context with the given value.
func SetClaim(ctx context.Context, claim *jwt.Claims) context.Context {
	// Add a context value to pass advisory information to the next handler.
	return context.WithValue(ctx, claimContextIDKey, claim)
}

// GetClaim attempts to extract the monitoring value from the given context.
func GetClaim(ctx context.Context) *jwt.Claims {
	if ctx == nil {
		return nil
	}
	value := ctx.Value(claimContextIDKey)
	if value == nil {
		return nil
	}
	return value.(*jwt.Claims)
}

const monitorSubject = "monitoring"

// IsMonitoring reports whether (possibly nil) claim is from a monitoring issuer.
func IsMonitoring(cl *jwt.Claims) bool {
	if cl == nil {
		return false
	}
	return cl.Subject == monitorSubject
}
