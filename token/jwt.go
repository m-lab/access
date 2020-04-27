// Package token provides support for parsing JSON Web Keys (JWK),
// creating signed JSON Web Tokens (JWT), and verifying JWT signatures.
package token

import (
	"errors"
	"fmt"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// ErrKeyIDNotFound is returned when trying to verify a token when there are no
// corresponding key IDs matching the token header.
var ErrKeyIDNotFound = errors.New("Key ID not found for given token header")

// ErrDuplicateKeyID is returned when initializing a verifier with multiple keys
// with the same KeyID. KeyIDs should be unique.
var ErrDuplicateKeyID = errors.New("Duplicate KeyID found")

// Verifier supports operations on a public JWK.
type Verifier struct {
	keys map[string]*jose.JSONWebKey
}

// Signer supports operations on a private JWK.
type Signer struct {
	jwt.Builder
}

// NewSigner accepts a serialized, private JWK and creates a new Signer instance.
func NewSigner(key []byte) (*Signer, error) {
	priv, err := LoadJSONWebKey(key, false)
	if err != nil {
		return nil, err
	}
	alg := jose.SignatureAlgorithm(priv.Algorithm)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: priv}, nil)
	p := &Signer{
		Builder: jwt.Signed(signer),
	}
	return p, err
}

// Sign generates a signed JWT in compact form.
func (k *Signer) Sign(cl jwt.Claims) (string, error) {
	// Create a builder for signed tokens, apply claims, and serialize.
	return k.Builder.Claims(cl).CompactSerialize()
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

// Claims extracts the claims from a signed token, but does not
// validate them against any expected claims. Useful for extracting
// only the claims object.
func (k *Verifier) Claims(token string) (*jwt.Claims, error) {
	obj, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, err
	}
	// NOTE: if ParseSigned returns without error, then we are guaranteed that
	// at least one header is present. And, we will not support tokens with
	// multiple signatures/headers.
	keyID := obj.Headers[0].KeyID
	pub, found := k.keys[keyID]
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrKeyIDNotFound, keyID)
	}
	// Claims validates the jwt signature before extracting the token claims.
	cl := &jwt.Claims{}
	err = obj.Claims(pub, cl)
	if err != nil {
		return nil, err
	}
	return cl, nil
}

// Verify checks the token signature and that the claims match the expected
// config. Note: if validation of the expected claims fails, then Verify will
// return the original token claims with the corresponding non-nil validation error.
func (k *Verifier) Verify(token string, exp jwt.Expected) (*jwt.Claims, error) {
	cl, err := k.Claims(token)
	if err != nil {
		return nil, err
	}
	// Verify that the expected claims satisfy the signed claims.
	err = cl.Validate(exp)
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
