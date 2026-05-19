package ligo_auth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type hmacSigner struct {
	secret []byte
}

// NewHMACSigner creates a Signer that verifies HMAC-signed JWTs (HS256/HS384/HS512).
func NewHMACSigner(secret HMACSecret) Signer {
	return &hmacSigner{secret: []byte(secret)}
}

func (s *hmacSigner) Verify(tokenString string) (map[string]any, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("auth: unexpected signing method %v", token.Header["alg"])
		}
		return s.secret, nil
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
