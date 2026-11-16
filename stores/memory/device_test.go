package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/device"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

// The store enforces the subset rule itself, independently of the service.
func TestDeviceStoreRefusesWidenedDecision(t *testing.T) {
	store := memory.NewDeviceStore()
	now := time.Now().UTC()
	user := auth.Digest{1}

	err := store.CreateAuthorization(context.Background(), device.Authorization{
		ID: "a", Device: auth.Digest{2}, User: user, ClientID: "cli",
		Scopes: []string{"read"}, CreatedAt: now,
		ExpiresAt: now.Add(time.Minute), Interval: time.Second,
		State: device.StatePending,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = store.Decide(context.Background(), user, now, device.Decision{
		Approve: true, Subject: "alice", Tenant: "acme",
		Scopes: []string{"read", "write"},
	})
	if !errors.Is(err, device.ErrScope) {
		t.Fatalf("widened decision accepted: %v", err)
	}
}
