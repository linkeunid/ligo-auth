# ligo-auth

JWT authentication extension for [Ligo](https://github.com/linkeunid/ligo). Verify-only — extracts tokens, verifies via HMAC/RSA/ECDSA signers, and attaches claims to request context as a `ligo.Guard`.

[![Go Version](https://img.shields.io/badge/go-1.25+-blue)](https://go.dev/dl)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-38%20passing-brightgreen)](https://github.com/linkeunid/ligo-auth)

## Install

```bash
go get github.com/ligo-auth
```

## Quick Start

```go
package main

import (
    "os"

    ligo "github.com/linkeunid/ligo"
    ligo_auth "github.com/ligo-auth"
)

func AppModule() ligo.Module {
    return ligo.NewModule("app",
        ligo.Imports(
            ligo_auth.Module(ligo_auth.Config{
                Signer: ligo_auth.NewHMACSigner(ligo_auth.HMACSecret(os.Getenv("JWT_SECRET"))),
            }),
        ),
        ligo.Providers(
            ligo.HookedFactory(NewUserController),
        ),
    )
}
```

## Protect Routes

```go
type UserController struct {
    auth *ligo_auth.AuthProvider
}

func NewUserController(auth *ligo_auth.AuthProvider) *UserController {
    return &UserController{auth: auth}
}

func (c *UserController) Routes(r ligo.Router) {
    cr := ligo.NewChainRouter(r.Group("/users"))

    cr.GET("/profile", c.Profile).
        Guard(c.auth.Guard()).
        Handle()

    cr.GET("/admin", c.AdminPanel).
        Guard(c.auth.Guard()).
        Guard(ligo.RolesGuard("admin")).
        Handle()

    cr.POST("", c.Create).Handle() // public
}

func (c *UserController) Profile(ctx *ligo.Context) error {
    claims := ligo_auth.ClaimsFromContext[ligo_auth.Claims](ctx)
    return ctx.JSON(200, claims)
}
```

## Signers

```go
// HMAC (HS256/HS384/HS512)
ligo_auth.NewHMACSigner(ligo_auth.HMACSecret("your-secret"))

// RSA (RS256/RS384/RS512)
ligo_auth.NewRSASigner(ligo_auth.RSAPublicKey(pemBytes))

// ECDSA (ES256/ES384/ES512)
ligo_auth.NewECDSASigner(ligo_auth.ECDSAPublicKey(pemBytes))
```

Typed key constants (`HMACSecret`, `RSAPublicKey`, `ECDSAPublicKey`) prevent accidental misuse at compile time.

## Token Extraction

Extractors are tried in order. First non-empty token wins.

```go
ligo_auth.Config{
    Extractors: []ligo_auth.Extractor{
        ligo_auth.BearerExtractor{},
        ligo_auth.CookieExtractor{Name: "access_token"},
        ligo_auth.HeaderExtractor{Name: "X-Access-Token"},
    },
}
```

Default: `BearerExtractor` alone.

## Custom Claims

```go
type MyClaims struct {
    ligo_auth.Claims
    Email string `json:"email"`
    OrgID string `json:"org_id"`
}

ligo_auth.Config{
    ClaimsFactory: func(raw map[string]any) (any, error) {
        b, _ := json.Marshal(raw)
        var c MyClaims
        json.Unmarshal(b, &c)
        return &c, nil
    },
}

// Retrieve in handler:
claims := ligo_auth.ClaimsFromContext[MyClaims](ctx)
```

## Manual Module Composition

Use `Provider()` for manual wiring without `Module()`:

```go
func MyModule() ligo.Module {
    return ligo.NewModule("my",
        ligo.Providers(
            ligo_auth.Provider(ligo_auth.Config{
                Signer: ligo_auth.NewHMACSigner(ligo_auth.HMACSecret("secret")),
            }),
        ),
    )
}
```

## Error Handling

`Guard()` returns `(false, error)` on failure. Combine with Ligo's exception filters:

| Scenario | Error |
|----------|-------|
| No token found | `auth: no token found` |
| Token expired/invalid | Wrapped JWT library error |
| ClaimsFactory fails | `auth: claims factory: <cause>` |

## License

MIT
