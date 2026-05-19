package ligo_auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAuthProvider_ExtractToken(t *testing.T) {
	p := newAuthProvider(Config{
		Signer:     NewHMACSigner(HMACSecret("secret")),
		Extractors: []Extractor{BearerExtractor{}, CookieExtractor{Name: "token"}},
	})

	t.Run("bearer token found", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer mytoken")
		token, err := p.extractToken(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "mytoken" {
			t.Errorf("token = %q, want %q", token, "mytoken")
		}
	})

	t.Run("fallback to cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "token", Value: "cookietoken"})
		token, err := p.extractToken(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "cookietoken" {
			t.Errorf("token = %q, want %q", token, "cookietoken")
		}
	})

	t.Run("no token found", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		_, err := p.extractToken(req)
		if err == nil {
			t.Fatal("expected error when no token found")
		}
	})
}

func TestAuthProvider_VerifyAndBuildClaims_Default(t *testing.T) {
	p := newAuthProvider(Config{
		Signer: NewHMACSigner(HMACSecret("secret")),
	})

	token := signHMACToken("secret", jwt.MapClaims{
		"sub":   "user-1",
		"roles": []any{"admin"},
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	claims, err := p.verifyAndBuildClaims(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	typed, ok := claims.(*Claims)
	if !ok {
		t.Fatalf("expected *Claims, got %T", claims)
	}
	if typed.Sub != "user-1" {
		t.Errorf("sub = %q, want %q", typed.Sub, "user-1")
	}
	if len(typed.Roles) != 1 || typed.Roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin]", typed.Roles)
	}
}

func TestAuthProvider_VerifyAndBuildClaims_CustomFactory(t *testing.T) {
	type CustomClaims struct {
		Claims
		Email string `json:"email"`
	}

	p := newAuthProvider(Config{
		Signer: NewHMACSigner(HMACSecret("secret")),
		ClaimsFactory: func(raw map[string]any) (any, error) {
			b, _ := json.Marshal(raw)
			var c CustomClaims
			json.Unmarshal(b, &c)
			return &c, nil
		},
	})

	token := signHMACToken("secret", jwt.MapClaims{
		"sub":   "user-1",
		"email": "test@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	claims, err := p.verifyAndBuildClaims(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	typed, ok := claims.(*CustomClaims)
	if !ok {
		t.Fatalf("expected *CustomClaims, got %T", claims)
	}
	if typed.Email != "test@example.com" {
		t.Errorf("email = %q, want %q", typed.Email, "test@example.com")
	}
}

func TestAuthProvider_VerifyAndBuildClaims_InvalidToken(t *testing.T) {
	p := newAuthProvider(Config{
		Signer: NewHMACSigner(HMACSecret("secret")),
	})

	_, err := p.verifyAndBuildClaims("invalid-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestNewAuthProvider_PanicsWithoutSigner(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic when Signer is nil")
		}
	}()
	newAuthProvider(Config{})
}

func TestNewAuthProvider_Defaults(t *testing.T) {
	p := newAuthProvider(Config{
		Signer: NewHMACSigner(HMACSecret("secret")),
	})
	if p.contextKey != "user" {
		t.Errorf("contextKey = %q, want %q", p.contextKey, "user")
	}
	if len(p.extractors) != 1 {
		t.Fatalf("expected 1 default extractor, got %d", len(p.extractors))
	}
	if _, ok := p.extractors[0].(BearerExtractor); !ok {
		t.Errorf("default extractor = %T, want BearerExtractor", p.extractors[0])
	}
}
