package ligo_auth

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type ecdsaSigner struct {
	pubKey *ecdsa.PublicKey
}

// NewECDSASigner creates a Signer that verifies ECDSA-signed JWTs (ES256/ES384/ES512).
// Panics if the PEM data cannot be parsed as an ECDSA public key.
func NewECDSASigner(pubKey ECDSAPublicKey) Signer {
	block, _ := pem.Decode(pubKey)
	if block == nil {
		panic("auth: failed to decode PEM block containing ECDSA public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("auth: failed to parse ECDSA public key: %v", err))
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		panic("auth: PEM does not contain ECDSA public key")
	}
	return &ecdsaSigner{pubKey: ecdsaPub}
}

func (s *ecdsaSigner) Verify(tokenString string) (map[string]any, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("auth: unexpected signing method %v", token.Header["alg"])
		}
		return s.pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("auth: verify token: %w", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("auth: invalid token claims")
	}
	return map[string]any(claims), nil
}
