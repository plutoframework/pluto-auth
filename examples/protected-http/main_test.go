package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestProtectedRouteAndRevocation(t *testing.T) {
	handler, manager, err := application()
	if err != nil {
		t.Fatal(err)
	}

	if response := request(
		handler,
		"",
	); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status: %d", response.Code)
	}

	issued, err := manager.Start(context.Background(), "synthetic-account")
	if err != nil {
		t.Fatal(err)
	}

	response := request(handler, issued.Token)
	if response.Code != http.StatusOK ||
		response.Body.String() != `{"authenticated":true}` {
		t.Fatalf(
			"authenticated response: %d %s",
			response.Code,
			response.Body.String(),
		)
	}

	if strings.Contains(response.Body.String(), issued.Token) {
		t.Fatal("response leaked credential")
	}

	if err := manager.Revoke(context.Background(), issued.Token); err != nil {
		t.Fatal(err)
	}

	if response := request(
		handler,
		issued.Token,
	); response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked status: %d", response.Code)
	}

	if response := request(
		handler,
		"malformed",
	); response.Code != http.StatusUnauthorized {
		t.Fatalf("malformed credential status: %d", response.Code)
	}
}
