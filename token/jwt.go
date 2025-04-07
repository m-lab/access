package token

import (
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var ErrKeyIDNotFound = errors.New("Key ID not found for given token header")
var ErrDuplicateKeyID = errors.New("Duplicate KeyID found")

type Verifier struct {
	keys map[string]*jose.JSONWebKey
}

type Signer struct {
	jwt.Builder
}

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
	}
	return p, nil
}

func (k *Signer) Sign(cl jwt.Claims) (string, error) {
	return k.Builder.Claims(cl).Serialize()
}

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

	keyID := headers[0].KeyID
	pub, found := k.keys[keyID]
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrKeyIDNotFound, keyID)
	}

	cl := &jwt.Claims{}
	err = tok.Claims(pub, cl)
	if err != nil {
		return nil, err
	}
	return cl, nil
}

func (k *Verifier) Verify(token string, exp jwt.Expected) (*jwt.Claims, error) {
	cl, err := k.Claims(token)
	if err != nil {
		return nil, err
	}
	err = cl.Validate(exp)
	return cl, err
}

// JWKS returns a JSON Web Key Set containing all public keys in the Verifier.
func (k *Verifier) JWKS() jose.JSONWebKeySet {
	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, 0, len(k.keys)),
	}

	for _, key := range k.keys {
		// Ensure we only add public keys to the JWKS
		jwks.Keys = append(jwks.Keys, key.Public())
	}

	return jwks
}

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
