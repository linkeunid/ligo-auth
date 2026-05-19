package ligo_auth

// Config configures the auth module.
type Config struct {
	// Signer verifies JWT tokens. Required — one of NewHMACSigner,
	// NewRSASigner, or NewECDSASigner.
	Signer Signer

	// Extractors tried in order. First non-empty token wins.
	// Default: [BearerExtractor] alone.
	Extractors []Extractor

	// ContextKey is the key used to store claims on the request context.
	// Default: "user".
	ContextKey string

	// ClaimsFactory maps raw JWT claims to a custom struct.
	// When set, the struct produced here is stored on context instead of
	// the default Claims. Use with ClaimsFromContext[T] to retrieve it.
	ClaimsFactory func(map[string]any) (any, error)
}
