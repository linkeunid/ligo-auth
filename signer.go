package ligo_auth

// Signer verifies JWT tokens and returns the raw claims.
type Signer interface {
	Verify(token string) (map[string]any, error)
}

// HMACSecret is a typed HMAC shared secret. Prevents accidental passing of
// PEM bytes where a secret string is expected.
//
//	ligo_auth.NewHMACSigner(ligo_auth.HMACSecret(os.Getenv("JWT_SECRET")))
type HMACSecret string

// RSAPublicKey is a PEM-encoded RSA public key for JWT verification.
//
//	ligo_auth.NewRSASigner(ligo_auth.RSAPublicKey(pemBytes))
type RSAPublicKey []byte

// ECDSAPublicKey is a PEM-encoded ECDSA public key for JWT verification.
//
//	ligo_auth.NewECDSASigner(ligo_auth.ECDSAPublicKey(pemBytes))
type ECDSAPublicKey []byte
