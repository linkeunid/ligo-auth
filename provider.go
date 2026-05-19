package ligo_auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/linkeunid/ligo"
)

const internalClaimsKey = "_ligo_auth_claims"

// AuthProvider is the singleton registered by [Module]. It exposes [Guard]
// which returns a [ligo.Guard] for use with Ligo's RouteBuilder.
type AuthProvider struct {
	signer        Signer
	extractors    []Extractor
	contextKey    string
	claimsFactory func(map[string]any) (any, error)
}

func newAuthProvider(cfg Config) *AuthProvider {
	if cfg.Signer == nil {
		panic("auth: Config.Signer is required")
	}
	extractors := cfg.Extractors
	if len(extractors) == 0 {
		extractors = []Extractor{BearerExtractor{}}
	}
	key := cfg.ContextKey
	if key == "" {
		key = "user"
	}
	return &AuthProvider{
		signer:        cfg.Signer,
		extractors:    extractors,
		contextKey:    key,
		claimsFactory: cfg.ClaimsFactory,
	}
}

// Guard returns a [ligo.Guard] that extracts a JWT, verifies it, and stores
// the claims on the request context.
//
//	cr.GET("/profile", c.Profile).Guard(authProvider.Guard())
func (p *AuthProvider) Guard() ligo.Guard {
	return func(ctx *ligo.Context) (bool, error) {
		token, err := p.extractToken(ctx.Request())
		if err != nil {
			return false, err
		}
		claims, err := p.verifyAndBuildClaims(token)
		if err != nil {
			return false, err
		}
		ctx.Set(p.contextKey, claims)
		ctx.Set(internalClaimsKey, claims)
		return true, nil
	}
}

// ClaimsFromContext retrieves the verified claims from the request context.
// T is the claims struct — use [Claims] for the default type, or your custom
// struct when [Config.ClaimsFactory] is configured.
//
//	claims := ligo_auth.ClaimsFromContext[ligo_auth.Claims](ctx)
func ClaimsFromContext[T any](ctx *ligo.Context) *T {
	val := ctx.Get(internalClaimsKey)
	if val == nil {
		return nil
	}
	typed, ok := val.(*T)
	if !ok {
		return nil
	}
	return typed
}

func (p *AuthProvider) extractToken(req *http.Request) (string, error) {
	for _, ext := range p.extractors {
		t, err := ext.Extract(req)
		if err != nil {
			return "", fmt.Errorf("auth: extract token: %w", err)
		}
		if t != "" {
			return t, nil
		}
	}
	return "", fmt.Errorf("auth: no token found")
}

func (p *AuthProvider) verifyAndBuildClaims(token string) (any, error) {
	raw, err := p.signer.Verify(token)
	if err != nil {
		return nil, err
	}
	if p.claimsFactory != nil {
		claims, factoryErr := p.claimsFactory(raw)
		if factoryErr != nil {
			return nil, fmt.Errorf("auth: claims factory: %w", factoryErr)
		}
		return claims, nil
	}
	var c Claims
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("auth: marshal claims: %w", err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("auth: unmarshal claims: %w", err)
	}
	return &c, nil
}
