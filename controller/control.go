// Package controller provides various access controllers for use in
// socket-based and HTTP-based services.
package controller

import (
	"context"
	"log"
	"net/http"

	// Alice package provides a light weight way to chain HTTP middleware functions.
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/justinas/alice"
)

// TODO: replace with constants from the locate service repository.
const (
	locateIssuer   = "locate"
	monitorSubject = "monitoring"
)

// Paths is used to specify resource names (paths) operated on by access controllers.
type Paths map[string]bool

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

// IsMonitoring reports whether (possibly nil) claim is from a monitoring issuer.
func IsMonitoring(cl *jwt.Claims) bool {
	if cl == nil {
		return false
	}
	return cl.Subject == monitorSubject
}

// Setup creates a sequence of access control http.Handlers. When the verifier
// is nil then the token controller will be excluded from the returned handler
// chain. When the tx controller is unconfigured then the tx controller will be
// excluded from the returned handler chain. Setup returns the TxController
// because it provides the Accepter interface for use by servers accepting raw
// TCP connections. See TxController.Accept for more information. When
// tokenRequired is true, then the token controller requires valid access tokens
// for the named machine.
func Setup(ctx context.Context, v Verifier, tokenRequired bool, machine string, txEnf, tkEnf Paths) (alice.Chain, *TxController) {
	// Controllers must be applied in specific order so that the tx controller
	// can access the access token claims (if present) to identify monitoring
	// requests. When token validation is successful, the validated claims are
	// added to the HTTP request context. The tx controller looks for claims in
	// the request context to determine if a request is monitoring (to allow it).
	ac := alice.New()

	// If the verifier is not nil, include the token limit.
	exp := jwt.Expected{
		Issuer:      locateIssuer,
		AnyAudience: jwt.Audience{machine},
	}
	token, err := NewTokenController(v, tokenRequired, exp, tkEnf)
	if err == nil {
		ac = ac.Append(token.Limit)
	} else {
		log.Printf("WARNING: token controller is disabled: %v", err)
	}

	// If the tx controller is successful, include the tx limit.
	tx, err := NewTxController(ctx, txEnf)
	if err == nil {
		ac = ac.Append(tx.Limit)
	} else {
		log.Printf("WARNING: tx controller is disabled: %v", err)
	}

	return ac, tx
}
