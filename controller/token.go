package controller

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"reflect"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	tokenAccessRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ndt_access_token_requests_total",
			Help: "Total number of NDT requests handled by the access tokencontroller.",
		},
		[]string{"request", "reason"},
	)
	requireTokens bool
	tokenIssuer   string
	machine       string
)

// ErrInvalidVerifier may be returned when creating a new TokenController.
var ErrInvalidVerifier = errors.New("verifier is invalid")

func init() {
	flag.BoolVar(&requireTokens, "tokencontroller.required", false, "Whether access tokens are required by HTTP-based clients.")
	flag.StringVar(&tokenIssuer, "tokencontroller.issuer", "locate.measurementlab.net", "The JWT issuer used to verify access tokens.")
	flag.StringVar(&machine, "tokencontroller.machine", "", "The machine name to expect in the JWT claims.")
}

// TokenController manages access control for clients providing access_token parameters.
type TokenController struct {
	token   Verifier
	machine string
}

// Verifier is used by the TokenController to verify JWT claims in access tokens.
type Verifier interface {
	Verify(token string, exp jwt.Expected) (*jwt.Claims, error)
}

// NewTokenController creates a new token controller.
func NewTokenController(verifier Verifier) (*TokenController, error) {
	if reflect.ValueOf(verifier).IsNil() {
		// NOTE: use reflect to extract the value because verifier interface
		// type is non-nil and "verifier == nil" otherwise fails.
		return nil, ErrInvalidVerifier
	}
	if machine == "" {
		return nil, jwt.ErrInvalidAudience
	}
	return &TokenController{
		token:   verifier,
		machine: machine,
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
	if token == "" && !requireTokens {
		// The access token is missing and tokens are not requried, so accept the request.
		tokenAccessRequests.WithLabelValues("accepted", "empty").Inc()
		return true, ctx
	}
	// Attempt to verify the token.
	cl, err := t.token.Verify(token, jwt.Expected{
		Issuer: tokenIssuer,
		// Do not Verify the Subject. After verification, caller can check the
		// claim Subject for monitoring, a specific IP address, or service name.
		Audience: jwt.Audience{t.machine}, // current server.
		Time:     time.Now(),
	})
	if err != nil {
		// The access token was invalid; reject this request.
		tokenAccessRequests.WithLabelValues("rejected", "invalid").Inc()
		return false, ctx
	}
	// If the claim Issuer was monitoring, set the context value so subsequent
	// access controllers can check the context to allow monitoring reqeusts.
	tokenAccessRequests.WithLabelValues("accepted", cl.Issuer).Inc()
	return true, SetClaim(ctx, cl)
}
