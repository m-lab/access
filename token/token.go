// Package token provides support for parsing JSON Web Keys (JWK),
// creating signed JSON Web Tokens (JWT), and verifying JWT signatures.
package token

import (
	"errors"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Verifier supports operations on a public JWK.
type Verifier struct {
	pub *jose.JSONWebKey
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

// NewVerifier accepts a serialized, public JWK and creates a new Verifier instance.
func NewVerifier(key []byte) (*Verifier, error) {
	pub, err := LoadJSONWebKey(key, true)
	if err != nil {
		return nil, err
	}
	return &Verifier{
		pub: pub,
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
	cl := &jwt.Claims{}
	// Claims validates the jwt signature before extracting the token claims.
	err = obj.Claims(k.pub, cl)
	if err != nil {
		return nil, err
	}
	return cl, nil
}

// Verify checks the token signature and that the claims match the expected
// config.
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
