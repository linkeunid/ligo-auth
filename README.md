# LigoAuth

A [brief description of what this extension provides] for [Ligo](https://github.com/linkeunid/ligo).

[![Go Version](https://imgshadge.io/badge/go-1.21+-blue)](https://go.dev/dl)
[![Tests](https://imgshadge.io/badge/tests-passing-brightgreen)](https://github.com/github.com/ligo-auth)

## Install

```bash
go get github.com/ligo-auth
```

## Quick start

```go
import (
    "github.com/ligo-auth"
    "github.com/linkeunid/ligo"
)

func MyModule() ligo.Module {
    return ligo.NewModule("my",
        ligo.Providers(
            ligo_auth.Provider[SomeType](),
            // ... other providers
        ),
    )
}
```

## See also

- [Documentation](docs/features/)
