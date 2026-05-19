package ligo_auth

import (
	"net/http"
	"strings"
)

// Extractor retrieves a raw JWT string from an HTTP request.
// Returns ("", nil) when no token is found — the caller tries the next extractor.
type Extractor interface {
	Extract(r *http.Request) (string, error)
}

// BearerExtractor reads the token from the Authorization: Bearer <token> header.
type BearerExtractor struct{}

func (BearerExtractor) Extract(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", nil
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", nil
	}
	return strings.TrimSpace(parts[1]), nil
}

// CookieExtractor reads the token from a named cookie.
type CookieExtractor struct {
	Name string
}

func (e CookieExtractor) Extract(r *http.Request) (string, error) {
	cookie, err := r.Cookie(e.Name)
	if err != nil {
		return "", nil
	}
	return cookie.Value, nil
}

// HeaderExtractor reads the token from a custom header.
type HeaderExtractor struct {
	Name string
}

func (e HeaderExtractor) Extract(r *http.Request) (string, error) {
	val := r.Header.Get(e.Name)
	if val == "" {
		return "", nil
	}
	return strings.TrimSpace(val), nil
}
