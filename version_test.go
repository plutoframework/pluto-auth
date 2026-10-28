package auth_test

import (
	"context"
	"testing"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

func TestVersionedRotation(t *testing.T) {
	store, err := memory.New(8)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := auth.New(store, auth.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := manager.StartVersioned(ctx, "account", 0); err == nil {
		t.Fatal("accepted missing credential fence")
	}
	issued, err := manager.StartVersioned(ctx, "account", 7)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := manager.Rotate(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Session.CredentialVersion != 7 {
		t.Fatal("rotation discarded credential fence")
	}
}
