package ligo_auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func signHMACToken(secret string, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := token.SignedString([]byte(secret))
	return s
}

func TestHMACSigner_Verify_Valid(t *testing.T) {
	signer := NewHMACSigner(HMACSecret("test-secret"))
	token := signHMACToken("test-secret", jwt.MapClaims{
		"sub":   "user-1",
		"roles": []any{"admin"},
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	claims, err := signer.Verify(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1", claims["sub"])
	}
}

func TestHMACSigner_Verify_Expired(t *testing.T) {
	signer := NewHMACSigner(HMACSecret("test-secret"))
	token := signHMACToken("test-secret", jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	_, err := signer.Verify(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestHMACSigner_Verify_WrongSecret(t *testing.T) {
	signer := NewHMACSigner(HMACSecret("correct-secret"))
	token := signHMACToken("wrong-secret", jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err := signer.Verify(token)
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestHMACSigner_Verify_Malformed(t *testing.T) {
	signer := NewHMACSigner(HMACSecret("test-secret"))
	_, err := signer.Verify("not.a.valid-token")
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestHMACSigner_Verify_WrongAlgorithm(t *testing.T) {
	signer := NewHMACSigner(HMACSecret("test-secret"))
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "user-1",
	})
	s, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	_, err := signer.Verify(s)
	if err == nil {
		t.Fatal("expected error for wrong algorithm")
	}
}

func generateRSAKeyPair(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privBytes := x509.MarshalPKCS1PrivateKey(key)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}))
	pubBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
	return privPEM, pubPEM
}

func signRSAToken(privKeyPEM string, claims jwt.MapClaims) string {
	block, _ := pem.Decode([]byte(privKeyPEM))
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, _ := token.SignedString(key)
	return s
}

func TestRSASigner_Verify_Valid(t *testing.T) {
	privPEM, pubPEM := generateRSAKeyPair(t)
	signer := NewRSASigner(RSAPublicKey(pubPEM))
	token := signRSAToken(privPEM, jwt.MapClaims{
		"sub":   "user-1",
		"roles": []any{"admin"},
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	claims, err := signer.Verify(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1", claims["sub"])
	}
}

func TestRSASigner_Verify_Expired(t *testing.T) {
	privPEM, pubPEM := generateRSAKeyPair(t)
	signer := NewRSASigner(RSAPublicKey(pubPEM))
	token := signRSAToken(privPEM, jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	_, err := signer.Verify(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestRSASigner_Verify_WrongKey(t *testing.T) {
	privPEM, _ := generateRSAKeyPair(t)
	_, pubPEM2 := generateRSAKeyPair(t)
	signer := NewRSASigner(RSAPublicKey(pubPEM2)) // different public key
	token := signRSAToken(privPEM, jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err := signer.Verify(token)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func generateECDSAKeyPair(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privBytes, _ := x509.MarshalECPrivateKey(key)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}))
	pubBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
	return privPEM, pubPEM
}

func signECDSAToken(privKeyPEM string, claims jwt.MapClaims) string {
	block, _ := pem.Decode([]byte(privKeyPEM))
	key, _ := x509.ParseECPrivateKey(block.Bytes)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	s, _ := token.SignedString(key)
	return s
}

func TestECDSASigner_Verify_Valid(t *testing.T) {
	privPEM, pubPEM := generateECDSAKeyPair(t)
	signer := NewECDSASigner(ECDSAPublicKey(pubPEM))
	token := signECDSAToken(privPEM, jwt.MapClaims{
		"sub":   "user-1",
		"roles": []any{"admin"},
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	claims, err := signer.Verify(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1", claims["sub"])
	}
}

func TestECDSASigner_Verify_Expired(t *testing.T) {
	privPEM, pubPEM := generateECDSAKeyPair(t)
	signer := NewECDSASigner(ECDSAPublicKey(pubPEM))
	token := signECDSAToken(privPEM, jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	_, err := signer.Verify(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestECDSASigner_Verify_WrongKey(t *testing.T) {
	privPEM1, _ := generateECDSAKeyPair(t)
	_, pubPEM2 := generateECDSAKeyPair(t)

	signer := NewECDSASigner(ECDSAPublicKey(pubPEM2))
	token := signECDSAToken(privPEM1, jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err := signer.Verify(token)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}
