package ligo_auth

import "testing"

func TestClaims_HasRole(t *testing.T) {
	c := &Claims{Roles: []string{"admin", "editor"}}
	if !c.HasRole("admin") {
		t.Error("expected admin role")
	}
	if !c.HasRole("editor") {
		t.Error("expected editor role")
	}
	if c.HasRole("viewer") {
		t.Error("should not have viewer role")
	}
}

func TestClaims_HasRole_Empty(t *testing.T) {
	c := &Claims{Roles: nil}
	if c.HasRole("admin") {
		t.Error("empty claims should have no roles")
	}
}
