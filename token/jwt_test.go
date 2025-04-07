package token

import (
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/go-test/deep"
	"github.com/m-lab/go/rtx"
)

func TestSignAndVerify(t *testing.T) {
	insecurePrivateTestKey := `{"use":"sig","kty":"EC","kid":"112","crv":"P-256","alg":"ES256",` +
		`"x":"V0NoRfUZ-fPACALnakvKtTyXJ5JtgAWlWm-0NaDWUOE","y":"RDbGu6RVhgJGKCTuya4_IzZhT1GzlEIA5ZkumEZ35Ag",` +
		`"d":"RXSpuTicBEL5GY-76cGgRXIEOB-q4hJ0vqydEnOztIY"}`
	insecurePublicTestKey := `{"use":"sig","kty":"EC","kid":"112","crv":"P-256","alg":"ES256",` +
		`"x":"V0NoRfUZ-fPACALnakvKtTyXJ5JtgAWlWm-0NaDWUOE","y":"RDbGu6RVhgJGKCTuya4_IzZhT1GzlEIA5ZkumEZ35Ag"}`
	tests := []struct {
		name                string
		skey                string
		vkey                string
		cl                  jwt.Claims
		exp                 jwt.Expected
		wantSignErr         bool
		wantVerifyErr       bool
		wantDuplicateKeyErr bool
	}{
		{
			name: "success",
			skey: insecurePrivateTestKey,
			vkey: insecurePublicTestKey,
			cl: jwt.Claims{
				Issuer:   "issuer",
				Audience: jwt.Audience{"mlab1", "mlab2"},
				Expiry:   jwt.NewNumericDate(time.Date(2019, time.December, 1, 1, 2, 0, 0, time.UTC).Add(time.Minute)),
			},
			exp: jwt.Expected{
				Issuer:      "issuer",
				AnyAudience: jwt.Audience{"mlab1"},
				Time:        time.Date(2019, time.December, 1, 1, 2, 0, 0, time.UTC),
			},
		},
		{
			name:        "error-bad-signing-key",
			skey:        `this-is-not-a-signing-key`,
			wantSignErr: true,
		},
		{
			name: "error-bad-verify-key",
			skey: insecurePrivateTestKey,
			vkey: `thi-is-not-a-verify-key`,
			cl: jwt.Claims{
				Issuer:   "issuer",
				Audience: jwt.Audience{"mlab1", "mlab2"},
				Expiry:   jwt.NewNumericDate(time.Date(2019, time.December, 1, 1, 2, 0, 0, time.UTC).Add(time.Minute)),
			},
			wantVerifyErr: true,
		},
		{
			name: "error-duplicate-verify-key-id",
			skey: insecurePrivateTestKey,
			vkey: insecurePublicTestKey,
			cl: jwt.Claims{
				Issuer:   "issuer",
				Audience: jwt.Audience{"mlab1", "mlab2"},
				Expiry:   jwt.NewNumericDate(time.Date(2019, time.December, 1, 1, 2, 0, 0, time.UTC).Add(time.Minute)),
			},
			wantVerifyErr:       true,
			wantDuplicateKeyErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewSigner([]byte(tt.skey))
			if tt.wantSignErr != (err != nil) {
				t.Errorf("NewSigner failed to parse key: %v", err)
				return
			}
			if s == nil {
				return
			}
			token, err := s.Sign(tt.cl)
			if err != nil {
				t.Fatalf("Failed to sign claim: %#v", tt.cl)
			}

			keys := [][]byte{
				[]byte(tt.vkey),
			}
			if tt.wantDuplicateKeyErr {
				// Append the verify key twice so there is a duplicate keyid.
				keys = append(keys, []byte(tt.vkey))
			}

			v, err := NewVerifier(keys...)
			if tt.wantVerifyErr != (err != nil) {
				t.Fatalf("NewVerifier failed to parse key: %v", err)
			}
			if v == nil {
				return
			}
			cl, err := v.Verify(token, tt.exp)
			if err != nil {
				t.Fatal("Failed to verify token")
			}
			if diff := deep.Equal(*cl, tt.cl); diff != nil {
				t.Fatalf("Failed to match claims: %v", diff)
			}
		})
	}
}

func TestVerifyErrors(t *testing.T) {
	insecurePublicTestKey := `{"use":"sig","kty":"EC","kid":"112","crv":"P-256","alg":"ES256",` +
		`"x":"V0NoRfUZ-fPACALnakvKtTyXJ5JtgAWlWm-0NaDWUOE","y":"RDbGu6RVhgJGKCTuya4_IzZhT1GzlEIA5ZkumEZ35Ag"}`
	key, err := LoadJSONWebKey([]byte(insecurePublicTestKey), true)
	rtx.Must(err, "Failed to load key")

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "error",
			token: "a.b.c",
		},
		{
			name: "error-verify-claims",
			// compact signature with deliberate corruption to parse successfully, but fail to verify.
			token: "eyJhbGciOiJFUzI1NiIsImtpZCI6IjExMiJ9.eyJhdWQiOlsibWxhYjEubGdhMDMiLCJtbGFiMi5hdGwwM" +
				"iJdLCJleHAiOjE1Nzk5MTc3MzksImlzcyI6ImxvY2F0ZS5tZWFzdXJlbWVudGxhYi5uZXQiLCJqdGkiOiJ3aGF" +
				"0d2hhdCIsInN1YiI6Im5kdCJ9.07Wmg_G-lDDuPz0dLsuXjZLZN8w37BGIN1RTUK4rSJ-3OIFtsZ9b7pVS0uHPUrD0kW9mbuv0Ouu_eD0v88Bp-w",
		},
		{
			name: "error-verify-token-without-keyid",
			// same token as above with the header replaced with an empty "{}" object.
			token: "e30K.eyJhdWQiOlsibWxhYjEubGdhMDMiLCJtbGFiMi5hdGwwM" +
				"iJdLCJleHAiOjE1Nzk5MTc3MzksImlzcyI6ImxvY2F0ZS5tZWFzdXJlbWVudGxhYi5uZXQiLCJqdGkiOiJ3aGF" +
				"0d2hhdCIsInN1YiI6Im5kdCJ9.07Wmg_G-lDDuPz0dLsuXjZLZN8w37BGIN1RTUK4rSJ-3OIFtsZ9b7pVS0uHPUrD0kW9mbuv0Ouu_eD0v88Bp-w",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &Verifier{
				keys: map[string]*jose.JSONWebKey{"112": key},
			}
			_, err := k.Verify(tt.token, jwt.Expected{})
			if err == nil {
				t.Errorf("Verifier.Verify() verified a corrupt signature! should return an error")
				return
			}
		})
	}
}

func TestLoadJSONWebKeyErrors(t *testing.T) {
	insecurePrivateTestKey := `{"use":"sig","kty":"EC","kid":"112","crv":"P-256","alg":"ES256","x":"V0NoRfUZ-fPACALnakvKtTyXJ5JtgAWlWm-0NaDWUOE",` +
		`"y":"RDbGu6RVhgJGKCTuya4_IzZhT1GzlEIA5ZkumEZ35Ag","d":"RXSpuTicBEL5GY-76cGgRXIEOB-q4hJ0vqydEnOztIY"}`
	insecurePublicTestKey := `{"use":"sig","kty":"EC","kid":"112","crv":"P-256","alg":"ES256","x":"V0NoRfUZ-fPACALnakvKtTyXJ5JtgAWlWm-0NaDWUOE",` +
		`"y":"RDbGu6RVhgJGKCTuya4_IzZhT1GzlEIA5ZkumEZ35Ag"}`
	want := &jose.JSONWebKey{
		Algorithm: string(jose.ES256),
	}

	// Private key with isPublic:true should return an error.
	_, err := LoadJSONWebKey([]byte(insecurePrivateTestKey), true)
	if err == nil {
		t.Errorf("LoadJSONWebKey() loaded private key as public: %v", err)
		return
	}

	// When public key and isPublic:true, then we expect to get the right key.
	got, err := LoadJSONWebKey([]byte(insecurePublicTestKey), true)
	if err != nil {
		t.Errorf("LoadJSONWebKey() loaded public key failed: %v", err)
	}
	if got.Algorithm != want.Algorithm {
		t.Errorf("LoadJSONWebKey() alg mismatch; got %q, want %q",
			got.Algorithm, want.Algorithm)
	}
}

func TestSignerJWKS(t *testing.T) {
	insecurePrivateTestKey := `{"use":"sig","kty":"EC","kid":"112","crv":"P-256","alg":"ES256",` +
		`"x":"V0NoRfUZ-fPACALnakvKtTyXJ5JtgAWlWm-0NaDWUOE","y":"RDbGu6RVhgJGKCTuya4_IzZhT1GzlEIA5ZkumEZ35Ag",` +
		`"d":"RXSpuTicBEL5GY-76cGgRXIEOB-q4hJ0vqydEnOztIY"}`

	// Create a new signer
	s, err := NewSigner([]byte(insecurePrivateTestKey))
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// Get the JWKS
	jwks := s.JWKS()

	// Verify the JWKS contains exactly one key
	if len(jwks.Keys) != 1 {
		t.Errorf("Expected JWKS to contain 1 key, got %d", len(jwks.Keys))
	}

	// Verify the key in JWKS is public
	if !jwks.Keys[0].IsPublic() {
		t.Error("Expected JWKS to contain only public key")
	}

	// Verify the key ID matches
	if jwks.Keys[0].KeyID != "112" {
		t.Errorf("Expected key ID '112', got '%s'", jwks.Keys[0].KeyID)
	}

	// Verify the algorithm matches
	if jwks.Keys[0].Algorithm != "ES256" {
		t.Errorf("Expected algorithm 'ES256', got '%s'", jwks.Keys[0].Algorithm)
	}
}
