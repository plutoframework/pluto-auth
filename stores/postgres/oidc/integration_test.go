package oidcpostgres

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/methods/oidc"
	"github.com/plutoframework/pluto-auth/methods/oidc/oidchttp"
	"github.com/plutoframework/pluto-auth/stores/postgres"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"
)

func database(t *testing.T) *pgxpool.Pool {
	t.Helper()

	address := os.Getenv("PLUTO_AUTH_TEST_DATABASE_URL")
	if address == "" {
		t.Skip("PLUTO_AUTH_TEST_DATABASE_URL required")
	}

	ctx := context.Background()

	admin, err := pgxpool.New(ctx, address)
	if err != nil {
		t.Fatal(err)
	}

	schema := "oidc_" + strings.ToLower(rand.Text())
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}

	cfg, err := pgxpool.ParseConfig(address)
	if err != nil {
		t.Fatal(err)
	}

	cfg.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(
		func() {
			pool.Close()

			_, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
			admin.Close()
		},
	)

	for _, migration := range []string{postgres.Schema, postgres.LocalSchema, postgres.AuthenticationSchema, postgres.ExternalSchema} {
		if _, err := pool.Exec(ctx, migration); err != nil {
			t.Fatal(err)
		}
	}

	return pool
}

func TestEncryptedTransactions(t *testing.T) {
	pool := database(t)
	ctx := context.Background()
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	store, err := New(pool, key, 1)
	if err != nil {
		t.Fatal(err)
	}

	browser := sha256.Sum256([]byte("trusted browser"))

	tx := oidc.Transaction{
		State:         strings.Repeat("s", 43),
		BrowserDigest: browser,
		Nonce: strings.Repeat(
			"n",
			43,
		),
		Verifier: strings.Repeat("v", 43),
		Expires:  time.Now().Add(time.Minute),
	}
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}

	var encrypted []byte
	if err := pool.QueryRow(ctx, "SELECT encrypted_proof FROM pluto_auth_oidc_transactions").
		Scan(&encrypted); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(encrypted), tx.Verifier) ||
		strings.Contains(string(encrypted), tx.Nonce) {
		t.Fatal("persisted plaintext")
	}

	second := tx

	second.State = strings.Repeat("t", 43)
	if store.Save(ctx, second) == nil {
		t.Fatal("capacity bypass")
	}

	if _, err := store.Consume(
		ctx,
		tx.State,
		sha256.Sum256([]byte("wrong")),
		time.Now(),
	); err == nil {
		t.Fatal("wrong browser")
	}

	var (
		successes atomic.Int32
		group     sync.WaitGroup
	)
	for range 12 {
		group.Go(func() {
			result, err := store.Consume(ctx, tx.State, browser, time.Now())
			if err == nil {
				if result.Nonce != tx.Nonce {
					t.Error("wrong proof")
				}

				successes.Add(1)
			}
		})
	}

	group.Wait()

	if successes.Load() != 1 {
		t.Fatalf("consumed %d times", successes.Load())
	}

	if err := store.Save(ctx, second); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(
		ctx,
		"UPDATE pluto_auth_oidc_transactions SET encrypted_proof = decode('01','hex')",
	); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Consume(
		ctx,
		second.State,
		browser,
		time.Now(),
	); err == nil {
		t.Fatal("accepted corrupt proof")
	}
}

func TestBrowserSignInAndAccountFence(t *testing.T) {
	pool := database(t)
	ctx := context.Background()
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	store, err := New(pool, key, 100)
	if err != nil {
		t.Fatal(err)
	}

	sessions, err := postgres.NewLocal(pool)
	if err != nil {
		t.Fatal(err)
	}

	manager, err := auth.New(sessions, auth.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: rsaKey},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	var (
		issuer, nonce, challenge string
		exchanges                atomic.Int32
	)

	provider := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				_ = json.NewEncoder(w).
					Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
			case "/keys":
				_ = json.NewEncoder(w).
					Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &rsaKey.PublicKey, Algorithm: "RS256", Use: "sig"}}})
			case "/token":
				exchanges.Add(1)

				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}

				hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				if base64.RawURLEncoding.EncodeToString(hash[:]) != challenge {
					t.Error("PKCE mismatch")
				}

				body, _ := json.Marshal(
					map[string]any{
						"iss":            issuer,
						"sub":            "federated-user",
						"aud":            "app",
						"nonce":          nonce,
						"exp":            time.Now().Add(time.Minute).Unix(),
						"iat":            time.Now().Unix(),
						"email":          "existing@example.com",
						"email_verified": true,
					},
				)

				signed, err := signer.Sign(body)
				if err != nil {
					t.Error(err)

					return
				}

				token, err := signed.CompactSerialize()
				if err != nil {
					t.Error(err)

					return
				}

				_ = json.NewEncoder(w).
					Encode(map[string]string{"id_token": token, "access_token": "private", "token_type": "Bearer"})
			default:
				http.NotFound(w, r)
			}
		}),
	)
	defer provider.Close()

	issuer = provider.URL
	hc := provider.Client()
	hc.Timeout = 5 * time.Second

	client, err := oidc.New(
		ctx,
		oidc.Config{
			Issuer:       issuer,
			ClientID:     "app",
			ClientSecret: "test-only",
			RedirectURL:  "https://app.example/callback",
			HTTPClient:   hc,
			Transactions: store,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	service, err := oidc.NewService(client, store, manager, true)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"https://evil.example", "//evil.example", "/%2fevil.example", "/%5cevil.example"} {
		_, err := oidchttp.New(
			service,
			oidchttp.Config{
				Transport: httpauth.Config{
					TrustedOrigins: []string{"https://app.example"},
				},
				Ingress:         func(h http.Handler) http.Handler { return h },
				SuccessPath:     path,
				CookieNamespace: "test-client",
			},
		)
		if err == nil {
			t.Fatalf("accepted unsafe success path %s", path)
		}
	}

	handler, err := oidchttp.New(
		service,
		oidchttp.Config{
			Transport: httpauth.Config{
				TrustedOrigins: []string{"https://app.example"},
			},
			Ingress:         func(h http.Handler) http.Handler { return h },
			SuccessPath:     "/settings",
			CookieNamespace: "test-client",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// A matching provider email does not bind to or verify this local account.
	if _, err := pool.Exec(
		ctx,
		"INSERT INTO pluto_auth_accounts(id,email,password_hash) VALUES('local','existing@example.com','not-a-real-hash')",
	); err != nil {
		t.Fatal(err)
	}

	begin := func() (*http.Cookie, string) {
		t.Helper()

		req := httptest.NewRequest("POST", "https://app.example/begin", nil)
		req.Header.Set("Origin", "https://app.example")

		result := httptest.NewRecorder()
		handler.ServeHTTP(result, req)

		if result.Code != 303 {
			t.Fatalf("begin status %d: %s", result.Code, result.Body.String())
		}

		parsed, _ := url.Parse(result.Header().Get("Location"))
		query := parsed.Query()
		nonce = query.Get("nonce")
		challenge = query.Get("code_challenge")

		return result.Result().Cookies()[0], query.Get("state")
	}
	callback := func(cookie *http.Cookie, query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(
			"GET",
			"https://app.example/callback?"+query,
			nil,
		)
		req.AddCookie(cookie)

		result := httptest.NewRecorder()
		handler.ServeHTTP(result, req)

		return result
	}
	badOrigin := httptest.NewRecorder()
	handler.ServeHTTP(
		badOrigin,
		httptest.NewRequest("POST", "https://app.example/begin", nil),
	)

	if badOrigin.Code != 403 {
		t.Fatal("missing Origin accepted")
	}

	cookie, state := begin()
	if result := callback(
		cookie,
		"state="+state+"&state="+state+"&code=test",
	); result.Code != 401 {
		t.Fatal("duplicate state")
	}

	wrong := *cookie

	wrong.Value = strings.Repeat("x", 43)
	if callback(&wrong, "state="+state+"&code=test").Code != 401 {
		t.Fatal("wrong browser")
	}

	result := callback(cookie, "state="+state+"&code=test")
	if result.Code != 303 || result.Header().Get("Location") != "/settings" {
		t.Fatalf("callback %d %s", result.Code, result.Body.String())
	}

	if result.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cacheable credentials")
	}

	var token string

	for _, cookie := range result.Result().Cookies() {
		if cookie.Name == httpauth.CookieName {
			token = cookie.Value
			if !cookie.Secure || !cookie.HttpOnly {
				t.Fatal("unsafe cookie")
			}
		}
	}

	session, err := manager.Authenticate(ctx, token)
	if err != nil || session.SubjectID == "local" ||
		session.Authentication.Primary != auth.MethodOIDC {
		t.Fatalf("wrong session: %v", err)
	}

	if callback(cookie, "state="+state+"&code=test").Code != 401 ||
		exchanges.Load() != 1 {
		t.Fatal("replay reached provider")
	}

	var email, hash string
	if err := pool.QueryRow(ctx, "SELECT email,password_hash FROM pluto_auth_accounts WHERE id=$1", session.SubjectID).
		Scan(&email, &hash); err != nil ||
		email != "" ||
		hash != "" {
		t.Fatal("placeholder credentials")
	}

	rotated, err := manager.Rotate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}

	if rotated.Session.Authentication.Primary != auth.MethodOIDC {
		t.Fatal("lost evidence")
	}

	if err := sessions.SetSecondFactorRequired(
		ctx,
		session.SubjectID,
		true,
	); err != nil {
		t.Fatal(err)
	}

	cookie, state = begin()
	if callback(cookie, "state="+state+"&code=test").Code != 401 {
		t.Fatal("required factor bypass")
	}

	if _, err := manager.Authenticate(ctx, rotated.Token); err == nil {
		t.Fatal("factor policy did not revoke")
	}

	if err := sessions.SetSecondFactorRequired(
		ctx,
		session.SubjectID,
		false,
	); err != nil {
		t.Fatal(err)
	}

	stale := rotated.Session
	stale.ID = "stale-issuance"

	staleDigest := sha256.Sum256([]byte("stale-session"))
	if err := sessions.CreateAuthenticated(
		ctx,
		staleDigest,
		stale,
	); err == nil {
		t.Fatal("stale account version issued")
	}

	if err := sessions.Disable(ctx, session.SubjectID); err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Authenticate(ctx, rotated.Token); err == nil {
		t.Fatal("disabled session accepted")
	}

	cookie, state = begin()
	if callback(cookie, "state="+state+"&code=test").Code != 401 {
		t.Fatal("disabled sign-in accepted")
	}
}
