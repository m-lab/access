// Package controller provides various access controllers for use in
// socket-based and HTTP-based services.
package controller

import (
	"context"
	"log"
	"net/http"

	"github.com/justinas/alice"
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

// Setup creates sequence of access control http.Handlers. If the
// verifier is nil then it will be excluded. If the tx controller is
// unconfigured then it will be excluded.
func Setup(ctx context.Context, v Verifier) (alice.Chain, *TxController) {
	// Setup sequence of access control http.Handlers.
	// Controllers must be applied in specific order:
	// 1. access token - to validate client and monitoring requests
	// 2. transmit - to make resource-aware decisions and allow monitoring
	ac := alice.New()

	// If the verifier is not nil, include the token limit.
	token, err := NewTokenController(v)
	if err == nil {
		ac = ac.Append(token.Limit)
	} else {
		log.Printf("WARNING: token controller is disabled: %v", err)
	}

	// If the tx controller is successful, include the tx limit.
	tx, err := NewTxController(ctx)
	if err == nil {
		ac = ac.Append(tx.Limit)
	} else {
		log.Printf("WARNING: tx controller is disabled: %v", err)
	}

	return ac, tx
}
