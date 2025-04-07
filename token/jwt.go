package token

import (
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var ErrKeyIDNotFound = errors.New("Key ID not found for given token header")
var ErrDuplicateKeyID = errors.New("Duplicate KeyID found")

// Verifier is a JWT verifier.
type Verifier struct {
	keys map[string]*jose.JSONWebKey
}

// Signer is a JWT signer.
type Signer struct {
	jwt.Builder
	key *jose.JSONWebKey
}

// NewSigner accepts a serialized, private JWK and creates a new Signer instance.
func NewSigner(key []byte) (*Signer, error) {
	priv, err := LoadJSONWebKey(key, false)
	if err != nil {
		return nil, err
	}

	opts := &jose.SignerOptions{}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(priv.Algorithm), Key: priv}, opts)
	if err != nil {
		return nil, err
	}

	p := &Signer{
		Builder: jwt.Signed(signer),
		key:     priv,
	}
	return p, nil
}

// Sign signs the given claims and returns the serialized token.
func (k *Signer) Sign(cl jwt.Claims) (string, error) {
	return k.Builder.Claims(cl).Serialize()
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

// Claims extracts the claims from a signed token, but does not
// validate them against any expected claims. Useful for extracting
// only the claims object.
func (k *Verifier) Claims(token string) (*jwt.Claims, error) {
	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{
		jose.EdDSA,
		jose.ES256,
		jose.RS256,
	})
	if err != nil {
		return nil, err
	}

	headers := tok.Headers
	if len(headers) == 0 {
		return nil, errors.New("no headers found in token")
	}

	// Note: We will not support tokens with multiple signatures/headers.
	keyID := headers[0].KeyID
	pub, found := k.keys[keyID]
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrKeyIDNotFound, keyID)
	}

	// Claims validates the jwt signature before extracting the token claims.
	cl := &jwt.Claims{}
	err = tok.Claims(pub, cl)
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
