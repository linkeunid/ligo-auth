package ligo_auth

import (
	"reflect"
	"testing"

	"github.com/linkeunid/ligo"
)

func TestModule_RegistersProvider(t *testing.T) {
	m := Module(Config{
		Signer: NewHMACSigner(HMACSecret("test")),
	})

	want := reflect.TypeFor[*AuthProvider]()
	found := false
	for _, raw := range m.Providers {
		if p, ok := raw.(ligo.Provider); ok && p.Type() == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Module must register *AuthProvider; providers: %v", m.Providers)
	}
}

func TestModule_Name(t *testing.T) {
	m := Module(Config{
		Signer: NewHMACSigner(HMACSecret("test")),
	})
	if m.Name != "auth" {
		t.Fatalf("module name = %q, want %q", m.Name, "auth")
	}
}

func TestProvider_ReturnsCorrectType(t *testing.T) {
	p := Provider(Config{
		Signer: NewHMACSigner(HMACSecret("test")),
	})
	want := reflect.TypeFor[*AuthProvider]()
	if p.Type() != want {
		t.Fatalf("provider type = %v, want %v", p.Type(), want)
	}
}
