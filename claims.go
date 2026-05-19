package ligo_auth

import "slices"

// Claims represents the standard JWT claims verified and attached to the
// request context. Embed this struct to add custom fields.
//
//	type MyClaims struct {
//	    ligo_auth.Claims
//	    Email string `json:"email"`
//	}
type Claims struct {
	Sub       string   `json:"sub"`
	Roles     []string `json:"roles"`
	Issuer    string   `json:"iss"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

// HasRole checks if the claims contain the given role.
// Satisfies the ligo.HasRole interface for use with ligo.RolesGuard.
func (c *Claims) HasRole(role string) bool {
	return slices.Contains(c.Roles, role)
}
