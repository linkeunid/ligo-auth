package ligo_auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type rsaSigner struct {
	pubKey *rsa.PublicKey
}

// NewRSASigner creates a Signer that verifies RSA-signed JWTs (RS256/RS384/RS512).
// Panics if the PEM data cannot be parsed as an RSA public key.
func NewRSASigner(pubKey RSAPublicKey) Signer {
	block, _ := pem.Decode(pubKey)
	if block == nil {
		panic("auth: failed to decode PEM block containing RSA public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("auth: failed to parse RSA public key: %v", err))
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		panic("auth: PEM does not contain RSA public key")
	}
	return &rsaSigner{pubKey: rsaPub}
}

func (s *rsaSigner) Verify(tokenString string) (map[string]any, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
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
