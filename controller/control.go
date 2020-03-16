// Package controller provides various access controllers for use in
// socket-based and HTTP-based services.
package controller

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
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
	ac := alice.New()

	// Controllers must be applied in specific order:
	// 1. logging
	// 2. access token handling
	// 3. transmit handling - must follow tokens to identify and allow monitoring
	ac = ac.Append(loggingHandler)

	// If the verifier is not nil, include the token limit.
	token, err := NewTokenController(v)
	if err == nil {
		ac = ac.Append(token.Limit)
	}

	// If the tx controller is successful, include the tx limit.
	tx, err := NewTxController(ctx)
	if err == nil {
		ac = ac.Append(tx.Limit)
	}

	return ac, tx
}

func loggingHandler(next http.Handler) http.Handler {
	return handlers.CustomLoggingHandler(os.Stderr, next, customFormat)
}

func customFormat(w io.Writer, p handlers.LogFormatterParams) {
	// Remove the RawQuery to print less unnecessary information.
	p.URL.RawQuery = ""
	fmt.Fprintln(w,
		p.Request.RemoteAddr,
		p.TimeStamp.Format(time.RFC3339Nano),
		p.Request.Proto,
		p.Request.Method,
		p.URL.String(),
		p.StatusCode,
		p.Size,
	)
}
