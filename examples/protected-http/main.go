// An in-process HTTP walkthrough with trusted synthetic session issuance.
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

func application() (http.Handler, *auth.Manager, error) {
	store, err := memory.New(100)
	if err != nil {
		return nil, nil, err
	}

	manager, err := auth.New(store, auth.DefaultConfig())
	if err != nil {
		return nil, nil, err
	}

	transport, err := httpauth.New(manager, httpauth.Config{
		TrustedOrigins: []string{"https://app.example.test"},
		AllowBearer:    true,
	})
	if err != nil {
		return nil, nil, err
	}

	account := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := httpauth.FromContext(r.Context())
		if !ok || session.SubjectID == "" {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		w.Header().Set("Content-Type", "application/json")

		_, _ = w.Write([]byte(`{"authenticated":true}`))
	})
	mux := http.NewServeMux()
	mux.Handle("GET /account", transport.Guard(transport.Require(account)))

	return mux, manager, nil
}

func request(handler http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(
		http.MethodGet,
		"https://app.example.test/account",
		nil,
	)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)

	return response
}

func main() {
	handler, manager, err := application()
	if err != nil {
		panic(err)
	}

	fmt.Println("anonymous:", request(handler, "").Code)

	// Trusted test setup, never a login route. Real apps verify credentials
	// before issuance and use the local credential service for password users.
	issued, err := manager.Start(context.Background(), "synthetic-account")
	if err != nil {
		panic(err)
	}

	fmt.Println("authenticated:", request(handler, issued.Token).Code)

	if err := manager.Revoke(context.Background(), issued.Token); err != nil {
		panic(err)
	}

	fmt.Println("revoked:", request(handler, issued.Token).Code)
}
