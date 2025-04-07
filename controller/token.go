package controller

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	tokenAccessRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "controller_access_token_requests_total",
			Help: "Total number of requests handled by the access tokencontroller.",
		},
		[]string{"path", "request", "reason"},
	)
)

// ErrInvalidVerifier may be returned when creating a new TokenController.
var ErrInvalidVerifier = errors.New("verifier is invalid")

// TokenController manages access control for clients providing access_token
// parameters in HTTP requests.
type TokenController struct {
	// Public is a public key access token verifier.
	Public Verifier

	// When access tokens are required, then clients without tokens are
	// rejected. When tokens are not required and clients do not provide an
	// access token the connection wil be allowed. In either case, when an
	// access token is provided it must be valid to be accepted.
	Required bool

	// Expected JWT fields are used to validate access token claims.
	// Client-provided claims are only valid if each non-empty expected field
	// matches the corresponding claims field.
	Expected jwt.Expected

	// Enforced is a set of HTTP request resource paths on which the
	// TokenController will enforce token authorization. Any resource missing
	// from the Enforced set is allowed.
	Enforced Paths
}

// Verifier is used by the TokenController to verify JWT claims in access
// tokens.
type Verifier interface {
	Verify(token string, exp jwt.Expected) (*jwt.Claims, error)
}

// NewTokenController creates a new token controller that requires tokens (or
// not) and the default expected claims. An audience must be specified. The
// issuer should be provided.
func NewTokenController(verifier Verifier, required bool, exp jwt.Expected, enforced Paths) (*TokenController, error) {
	if enforced == nil {
		return nil, ErrNilPaths
	}
	if reflect.ValueOf(verifier).IsNil() {
		// NOTE: use reflect to extract the value because verifier interface
		// type is non-nil and "verifier == nil" otherwise fails.
		return nil, ErrInvalidVerifier
	}
	if exp.Issuer == "" {
		return nil, jwt.ErrInvalidIssuer
	}
	if exp.AnyAudience == nil || exp.AnyAudience.Contains("") {
		return nil, jwt.ErrInvalidAudience
	}
	return &TokenController{
		Public:   verifier,
		Required: required,
		Expected: exp,
		Enforced: enforced,
	}, nil
}

// Limit checks client-provided access_tokens. Limit implements the Controller interface.
func (t *TokenController) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verified, ctx := t.isVerified(r)
		if !verified {
			// 403 - https://tools.ietf.org/html/rfc7231#section-6.5.3
			w.WriteHeader(http.StatusUnauthorized)
			// Return without additional response.
			return
		}
		// Clone the request with the context provided by isVerified.
		next.ServeHTTP(w, r.Clone(ctx))
	})
}

// isVerified validates the client-provided access_token. If the access_token is
// not found and tokens are not required, the request will be accepted. If the
// token is valid, then the returned context will include a boolean value
// indicating whether the token issuer is "monitoring" or not.
func (t *TokenController) isVerified(r *http.Request) (bool, context.Context) {
	ctx := r.Context()
	// NOTE: r.Form is not populated until calling ParseForm.
	r.ParseForm()
	token := r.Form.Get("access_token")
	pathLabel := "unknown"
	if !t.Enforced[r.URL.Path] {
		// This path is not in the Enforced set, so accept the connection.
		tokenAccessRequests.WithLabelValues(pathLabel, "accepted", "unenforced-path").Inc()
		return true, ctx
	}

	// The path is an enforced path, so copy it wholesale as a label.
	pathLabel = r.URL.Path
	if token == "" && !t.Required {
		// The access token is missing and tokens are not requried, so accept the request.
		tokenAccessRequests.WithLabelValues(pathLabel, "accepted", "empty").Inc()
		return true, ctx
	}
	if token == "" {
		// The access token was required but not provided.
		tokenAccessRequests.WithLabelValues(pathLabel, "rejected", "missing").Inc()
		return false, ctx
	}
	// Attempt to verify the token.
	exp := t.Expected
	exp.Time = time.Now()
	cl, err := t.Public.Verify(token, exp)
	if err != nil {
		// The access token was invalid; reject this request.
		reason := strings.TrimPrefix(err.Error(), "square/go-jose/jwt: validation failed, ")
		tokenAccessRequests.WithLabelValues(pathLabel, "rejected", reason).Inc()
		return false, ctx
	}
	// If the claim Issuer was monitoring, set the context value so subsequent
	// access controllers can check the context to allow monitoring reqeusts.
	tokenAccessRequests.WithLabelValues(pathLabel, "accepted", cl.Issuer).Inc()
	return true, SetClaim(ctx, cl)
}
