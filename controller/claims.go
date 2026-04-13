package controller

import "context"

type customClaimContextKeyType struct{}

var customClaimContextKey = customClaimContextKeyType{}

// SetCustomClaim returns a derived context carrying the given caller-defined
// claim value. The value is typically a pointer to a struct populated by
// Verifier.Verify via its variadic destination argument.
func SetCustomClaim(ctx context.Context, v any) context.Context {
	return context.WithValue(ctx, customClaimContextKey, v)
}

// GetCustomClaim returns the caller-defined claim value previously stored via
// SetCustomClaim, or nil if none is present. Callers are expected to type
// assert the returned value to their own claim type.
func GetCustomClaim(ctx context.Context) any {
	if ctx == nil {
		return nil
	}
	return ctx.Value(customClaimContextKey)
}
