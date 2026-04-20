// Package token provides support for parsing JSON Web Keys (JWK),
// creating signed JSON Web Tokens (JWT), and verifying JWT signatures.
package token

import (
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// ErrKeyIDNotFound is returned when trying to verify a token when there are no
// corresponding key IDs matching the token header.
var ErrKeyIDNotFound = errors.New("Key ID not found for given token header")

// supportedAlgorithms lists the signature algorithms accepted during token parsing.
var supportedAlgorithms = []jose.SignatureAlgorithm{
	jose.EdDSA,
	jose.ES256,
	jose.RS256,
}

// ErrDuplicateKeyID is returned when initializing a verifier with multiple keys
// with the same KeyID. KeyIDs should be unique.
var ErrDuplicateKeyID = errors.New("Duplicate KeyID found")

// Verifier is a JWT verifier. Requires a public JWK.
type Verifier struct {
	keys map[string]*jose.JSONWebKey
}

// Signer is a JWT signer. Requires a private JWK.
type Signer struct {
	builder jwt.Builder
	key     *jose.JSONWebKey
}

// NewSigner accepts a serialized, private JWK and creates a new Signer instance.
func NewSigner(key []byte) (*Signer, error) {
	priv, err := LoadJSONWebKey(key, false)
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(priv.Algorithm), Key: priv}, &jose.SignerOptions{})
	if err != nil {
		return nil, err
	}
	return &Signer{
		builder: jwt.Signed(signer),
		key:     priv,
	}, nil
}

// Sign signs the given claims and returns the serialized token. Optional extra
// claim objects are merged into the JWT payload via go-jose's Builder.Claims().
// If a field in extra serializes to a JSON key that is also set by cl, the
// standard claim wins: extras are applied first and cl last, so go-jose's
// later-wins merge semantics make cl authoritative.
func (s *Signer) Sign(cl jwt.Claims, extra ...any) (string, error) {
	b := s.builder
	for _, e := range extra {
		b = b.Claims(e)
	}
	return b.Claims(cl).Serialize()
}

// JWKS returns a JSON Web Key Set containing the public key for this signer
func (s *Signer) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{s.key.Public()},
	}
}

// NewVerifier accepts serialized, public JWKs and creates a new Verifier
// instance. Caller may pass multiple verifier keys to recognize and support key
// rotation of signer keys, or multiple issuers. When providing multiple keys
// each must have a distinct "keyid". An error derived from ErrDuplicateKeyID is
// returned when keys have the same keyid.
func NewVerifier(keys ...[]byte) (*Verifier, error) {
	pubKeys := map[string]*jose.JSONWebKey{}
	for i := range keys {
		pub, err := LoadJSONWebKey(keys[i], true)
		if err != nil {
			return nil, err
		}
		if _, dupKeyID := pubKeys[pub.KeyID]; dupKeyID {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateKeyID, pub.KeyID)
		}
		pubKeys[pub.KeyID] = pub
	}
	return &Verifier{
		keys: pubKeys,
	}, nil
}

// parsedToken parses a signed token string and resolves the signing key.
func (k *Verifier) parsedToken(token string) (*jwt.JSONWebToken, *jose.JSONWebKey, error) {
	tok, err := jwt.ParseSigned(token, supportedAlgorithms)
	if err != nil {
		return nil, nil, err
	}
	headers := tok.Headers
	if len(headers) == 0 {
		return nil, nil, errors.New("no headers found in token")
	}
	// Note: We will not support tokens with multiple signatures/headers.
	keyID := headers[0].KeyID
	pub, found := k.keys[keyID]
	if !found {
		return nil, nil, fmt.Errorf("%w: %s", ErrKeyIDNotFound, keyID)
	}
	return tok, pub, nil
}

// Claims extracts the claims from a signed token, but does not
// validate them against any expected claims. Useful for extracting
// only the claims object.
func (k *Verifier) Claims(token string) (*jwt.Claims, error) {
	tok, pub, err := k.parsedToken(token)
	if err != nil {
		return nil, err
	}
	cl := &jwt.Claims{}
	if err := tok.Claims(pub, cl); err != nil {
		return nil, err
	}
	return cl, nil
}

// Verify checks the token signature and validates claims against expected
// values. Extra destination pointers are unmarshaled from the same JWT payload
// via go-jose's variadic Claims support. For example:
//
//	var custom MyCustomClaims
//	cl, err := v.Verify(token, expected, &custom)
//
// If parsing succeeds but expected-claims validation fails, Verify returns the
// parsed claims along with the non-nil validation error.
func (k *Verifier) Verify(token string, exp jwt.Expected, extraDest ...any) (*jwt.Claims, error) {
	tok, pub, err := k.parsedToken(token)
	if err != nil {
		return nil, err
	}
	cl := &jwt.Claims{}
	dest := make([]any, 0, 1+len(extraDest))
	dest = append(dest, cl)
	dest = append(dest, extraDest...)
	if err := tok.Claims(pub, dest...); err != nil {
		return nil, err
	}
	// Verify that the expected claims satisfy the signed claims. Default leeway
	// for Validate() would be 1*time.Minute. This sets it to 0.
	err = cl.ValidateWithLeeway(exp, 0)
	return cl, err
}

// LoadJSONWebKey loads and validates the given JWK.
func LoadJSONWebKey(json []byte, isPublic bool) (*jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
	err := jwk.UnmarshalJSON(json)
	if err != nil {
		return nil, err
	}
	if !jwk.Valid() || jwk.IsPublic() != isPublic {
		return nil, errors.New("invalid JSON web key")
	}
	return &jwk, nil
}
