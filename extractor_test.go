package ligo_auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerExtractor_Extract(t *testing.T) {
	ext := BearerExtractor{}

	t.Run("valid bearer token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer abc123")
		token, err := ext.Extract(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "abc123" {
			t.Errorf("token = %q, want %q", token, "abc123")
		}
	})

	t.Run("missing header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		token, err := ext.Extract(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "" {
			t.Errorf("expected empty token, got %q", token)
		}
	})

	t.Run("non-bearer scheme", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Basic abc123")
		token, err := ext.Extract(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "" {
			t.Errorf("expected empty token for non-bearer, got %q", token)
		}
	})

	t.Run("trimmed whitespace", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer  abc123  ")
		token, err := ext.Extract(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "abc123" {
			t.Errorf("token = %q, want %q", token, "abc123")
		}
	})
}

func TestCookieExtractor_Extract(t *testing.T) {
	ext := CookieExtractor{Name: "access_token"}

	t.Run("cookie present", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "access_token", Value: "abc123"})
		token, err := ext.Extract(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "abc123" {
			t.Errorf("token = %q, want %q", token, "abc123")
		}
	})

	t.Run("cookie absent", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		token, err := ext.Extract(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "" {
			t.Errorf("expected empty token, got %q", token)
		}
	})

	t.Run("wrong cookie name", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "other_cookie", Value: "xyz"})
		token, err := ext.Extract(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "" {
			t.Errorf("expected empty token for wrong cookie, got %q", token)
		}
	})
}

func TestHeaderExtractor_Extract(t *testing.T) {
	ext := HeaderExtractor{Name: "X-Access-Token"}

	t.Run("header present", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Access-Token", "abc123")
		token, err := ext.Extract(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "abc123" {
			t.Errorf("token = %q, want %q", token, "abc123")
		}
	})

	t.Run("header absent", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		token, err := ext.Extract(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "" {
			t.Errorf("expected empty token, got %q", token)
		}
	})

	t.Run("trimmed whitespace", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Access-Token", "  abc123  ")
		token, err := ext.Extract(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "abc123" {
			t.Errorf("token = %q, want %q", token, "abc123")
		}
	})
}
