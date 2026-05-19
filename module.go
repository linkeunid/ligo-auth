package ligo_auth

import "github.com/linkeunid/ligo"

// Module returns a Ligo module that registers an [*AuthProvider] singleton.
// The provider is exported so sibling modules can inject it.
//
//	app.Register(
//	    ligo_auth.Module(ligo_auth.Config{
//	        Signer: ligo_auth.NewHMACSigner(ligo_auth.HMACSecret("secret")),
//	    }),
//	    userModule(),
//	)
func Module(cfg Config) ligo.Module {
	return ligo.NewModule("auth",
		ligo.Providers(
			ligo.Export(ligo.Factory[*AuthProvider](func() *AuthProvider {
				return newAuthProvider(cfg)
			})),
		),
	)
}

// Provider returns a [ligo.Provider] for manual module composition.
func Provider(cfg Config) ligo.Provider {
	return ligo.Factory[*AuthProvider](func() *AuthProvider {
		return newAuthProvider(cfg)
	})
}
