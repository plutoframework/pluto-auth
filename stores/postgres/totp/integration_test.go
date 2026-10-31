package totppostgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/plutoframework/pluto-auth/methods/password"
	"github.com/plutoframework/pluto-auth/methods/totp"
	"github.com/plutoframework/pluto-auth/methods/totp/totphttp"
	"github.com/plutoframework/pluto-auth/stores/postgres"

	"github.com/jackc/pgx/v5/pgxpool"
)

func database(t *testing.T) *pgxpool.Pool {
	t.Helper()

	address := os.Getenv("PLUTO_AUTH_TEST_DATABASE_URL")
	if address == "" {
		t.Skip("PLUTO_AUTH_TEST_DATABASE_URL required (disposable database)")
	}

	ctx := context.Background()

	admin, err := pgxpool.New(ctx, address)
	if err != nil {
		t.Fatal(err)
	}

	schema := "totp_" + strings.ToLower(rand.Text())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}

	config, err := pgxpool.ParseConfig(address)
	if err != nil {
		t.Fatal(err)
	}

	config.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err := pgxpool.NewWithConfig(ctx, config)
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

	for _, migration := range []string{postgres.Schema, postgres.LocalSchema, postgres.AuthenticationSchema, postgres.ExternalSchema, postgres.TOTPSchema} {
		if _, err := pool.Exec(ctx, migration); err != nil {
			t.Fatal(err)
		}
	}

	return pool
}

type sender struct{ notification password.Notification }

func (s *sender) Send(_ context.Context, n password.Notification) error {
	s.notification = n
	return nil
}

type harness struct {
	pool     *pgxpool.Pool
	store    *Store
	service  *totp.Service
	password *password.Service
	sender   *sender
	seed     []byte
	codes    []string
}

func setup(t *testing.T) *harness {
	t.Helper()

	ctx := context.Background()
	pool := database(t)

	store, err := New(pool)
	if err != nil {
		t.Fatal(err)
	}

	protector, err := totp.NewAESProtector(
		1,
		map[uint32][]byte{1: bytes.Repeat([]byte{9}, 32)},
	)
	if err != nil {
		t.Fatal(err)
	}

	limiter, err := password.NewWindowLimiter(1000, 1000, time.Minute, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	hasher, err := password.NewHasher(
		password.Config{
			MemoryKiB:     19 * 1024,
			Iterations:    2,
			Parallelism:   1,
			MaxConcurrent: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	sender := &sender{}

	primary, err := password.NewService(
		ctx,
		store,
		hasher,
		limiter,
		sender,
		auth.DefaultConfig(),
		password.DefaultLifecycleConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}

	service, err := totp.New(
		store,
		protector,
		limiter,
		totp.Config{Issuer: "Test", Sessions: auth.DefaultConfig()},
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := primary.Enroll(
		ctx,
		"alice@example.com",
		[]byte("long password test"),
	); err != nil {
		t.Fatal(err)
	}

	if err := primary.VerifyEmail(ctx, sender.notification.Token); err != nil {
		t.Fatal(err)
	}

	h := &harness{
		pool:     pool,
		store:    store,
		service:  service,
		password: primary,
		sender:   sender,
	}

	old, err := primary.SignIn(
		ctx,
		"alice@example.com",
		[]byte("long password test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	browser := totp.Browser()
	pending := h.begin(t, browser, totp.Enroll)

	uri, err := url.Parse(pending.URI)
	if err != nil {
		t.Fatal(err)
	}

	h.seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(uri.Query().Get("secret"))
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.Finish(
		ctx,
		pending.Challenge,
		browser,
		"",
		false,
		otp(h.seed, time.Now().Unix()/30-1),
	)
	if err != nil {
		t.Fatal(err)
	}

	h.codes = result.RecoveryCodes
	if len(h.codes) != 10 {
		t.Fatal("missing recovery")
	}

	if _, err := primary.Sessions().Authenticate(ctx, old.Token); err == nil {
		t.Fatal("enrollment retained old session")
	}

	return h
}

func (h *harness) begin(
	t *testing.T,
	browser string,
	action totp.Action,
) totp.Setup {
	t.Helper()

	ceremony, err := h.password.BeginSignIn(
		context.Background(),
		"alice@example.com",
		[]byte("long password test"),
	)
	if err != nil {
		t.Fatal(err)
	}

	pending, err := h.service.Begin(
		context.Background(),
		ceremony,
		browser,
		action,
		"alice@example.com",
	)
	if err != nil {
		t.Fatal(err)
	}

	return pending
}

func otp(seed []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))

	mac := hmac.New(sha1.New, seed)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	return fmt.Sprintf("%06d", value%1000000)
}

func TestNativeSignInReplayAndRecovery(t *testing.T) {
	h := setup(t)

	ctx := context.Background()
	if _, err := h.password.SignIn(
		ctx,
		"alice@example.com",
		[]byte("long password test"),
	); !errors.Is(
		err,
		auth.ErrAuthenticationRequired,
	) {
		t.Fatal("password bypass", err)
	}

	browser := totp.Browser()

	pending := h.begin(t, browser, totp.SignIn)
	if _, err := h.service.Sessions().
		Authenticate(ctx, pending.Challenge); err == nil {
		t.Fatal("pending became session")
	}

	if _, err := h.service.Finish(
		ctx,
		pending.Challenge,
		totp.Browser(),
		h.codes[0],
		true,
		"",
	); !errors.Is(
		err,
		totp.ErrDenied,
	) {
		t.Fatal("browser bypass")
	}

	result, err := h.service.Finish(
		ctx,
		pending.Challenge,
		browser,
		otp(h.seed, time.Now().Unix()/30),
		false,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	session, err := h.service.Sessions().Authenticate(ctx, result.Issued.Token)
	if err != nil || session.Authentication.SecondFactor != auth.MethodTOTP {
		t.Fatal("factor evidence", err)
	}

	rotated, err := h.service.Sessions().Rotate(ctx, result.Issued.Token)
	if err != nil || rotated.Session.Authentication != session.Authentication ||
		!rotated.Session.ExpiresAt.Equal(session.ExpiresAt) {
		t.Fatal("rotation changed evidence", err)
	}

	pending = h.begin(t, browser, totp.SignIn)
	if _, err := h.service.Finish(
		ctx,
		pending.Challenge,
		browser,
		otp(h.seed, time.Now().Unix()/30),
		false,
		"",
	); !errors.Is(
		err,
		totp.ErrDenied,
	) {
		t.Fatal("OTP replay")
	}

	var (
		successes atomic.Int32
		group     sync.WaitGroup
	)
	for range 12 {
		group.Go(func() {
			result, err := h.service.Finish(
				ctx,
				pending.Challenge,
				browser,
				h.codes[0],
				true,
				"",
			)
			if err == nil {
				successes.Add(1)

				if result.Issued.Session.Authentication.SecondFactor != auth.MethodRecoveryCode {
					t.Error("wrong recovery evidence")
				}
			} else if !errors.Is(err, totp.ErrDenied) {
				t.Error(err)
			}
		})
	}

	group.Wait()

	if successes.Load() != 1 {
		t.Fatalf("parallel successes: %d", successes.Load())
	}

	pending = h.begin(t, browser, totp.SignIn)
	if _, err := h.service.Finish(
		ctx,
		pending.Challenge,
		browser,
		h.codes[0],
		true,
		"",
	); !errors.Is(
		err,
		totp.ErrDenied,
	) {
		t.Fatal("recovery reuse")
	}

	var encrypted []byte
	if err := h.pool.QueryRow(ctx, "SELECT encrypted_seed FROM pluto_auth_totp_factors").
		Scan(&encrypted); err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(encrypted, h.seed) {
		t.Fatal("plaintext seed")
	}

	var digests [][]byte

	rows, err := h.pool.Query(
		ctx,
		"SELECT digest FROM pluto_auth_totp_recovery",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var value []byte
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}

		digests = append(digests, value)
	}

	if len(digests) != 9 {
		t.Fatal("recovery not consumed")
	}

	for _, d := range digests {
		for _, code := range h.codes {
			if bytes.Contains(d, []byte(code)) || len(d) != 32 {
				t.Fatal("plaintext recovery")
			}
		}
	}

	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestFactorLifecycleAndPasswordReset(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	browser := totp.Browser()

	pending := h.begin(t, browser, totp.SignIn)
	if err := h.password.RequestRecovery(ctx, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	if err := h.password.ResetPassword(
		ctx,
		h.sender.notification.Token,
		[]byte("long password test"),
	); err != nil {
		t.Fatal(err)
	}

	if _, err := h.service.Finish(
		ctx,
		pending.Challenge,
		browser,
		h.codes[0],
		true,
		"",
	); !errors.Is(
		err,
		totp.ErrDenied,
	) {
		t.Fatal("reset race")
	}

	account, err := h.store.LookupAccount(ctx, "alice@example.com")
	if err != nil || !account.SecondFactorRequired || account.Version < 3 {
		t.Fatal("reset lost factor policy/version", err)
	}

	if _, err := h.password.SignIn(
		ctx,
		"alice@example.com",
		[]byte("long password test"),
	); !errors.Is(
		err,
		auth.ErrAuthenticationRequired,
	) {
		t.Fatal("reset downgraded factor")
	}

	pending = h.begin(t, browser, totp.Regenerate)

	result, err := h.service.Finish(
		ctx,
		pending.Challenge,
		browser,
		h.codes[1],
		true,
		"",
	)
	if err != nil || len(result.RecoveryCodes) != 10 {
		t.Fatal(err)
	}

	oldCodes := h.codes
	h.codes = result.RecoveryCodes
	pending = h.begin(t, browser, totp.Replace)
	uri, _ := url.Parse(pending.URI)

	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(uri.Query().Get("secret"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.service.Finish(
		ctx,
		pending.Challenge,
		browser,
		oldCodes[2],
		true,
		otp(seed, time.Now().Unix()/30),
	); !errors.Is(
		err,
		totp.ErrDenied,
	) {
		t.Fatal("old recovery retained")
	}

	if _, err := h.service.Finish(
		ctx,
		pending.Challenge,
		browser,
		h.codes[0],
		true,
		"0000000",
	); !errors.Is(
		err,
		totp.ErrDenied,
	) {
		t.Fatal("unconfirmed replacement")
	}

	result, err = h.service.Finish(
		ctx,
		pending.Challenge,
		browser,
		h.codes[0],
		true,
		otp(seed, time.Now().Unix()/30),
	)
	if err != nil {
		t.Fatal(err)
	}

	h.codes = result.RecoveryCodes

	pending = h.begin(t, browser, totp.Remove)
	if _, err := h.service.Finish(
		ctx,
		pending.Challenge,
		browser,
		h.codes[0],
		true,
		"",
	); err != nil {
		t.Fatal(err)
	}

	if _, err := h.password.SignIn(
		ctx,
		"alice@example.com",
		[]byte("long password test"),
	); err != nil {
		t.Fatal("explicit removal failed", err)
	}
}

func TestRecoveryRollbackAndDisableFence(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	browser := totp.Browser()
	pending := h.begin(t, browser, totp.SignIn)
	// Force failure after proof consumption, proving the entire operation rolls back.
	_, err := h.pool.Exec(
		ctx,
		`CREATE FUNCTION fail_session() RETURNS trigger LANGUAGE plpgsql AS
  $$ BEGIN RAISE EXCEPTION 'test rollback'; END $$;
  CREATE TRIGGER fail_session BEFORE INSERT ON pluto_auth_sessions
  FOR EACH ROW EXECUTE FUNCTION fail_session()`,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.service.Finish(
		ctx,
		pending.Challenge,
		browser,
		h.codes[0],
		true,
		"",
	); !errors.Is(
		err,
		totp.ErrUnavailable,
	) {
		t.Fatal("expected rollback", err)
	}

	if _, err := h.pool.Exec(
		ctx,
		"DROP TRIGGER fail_session ON pluto_auth_sessions",
	); err != nil {
		t.Fatal(err)
	}

	if _, err := h.service.Finish(
		ctx,
		pending.Challenge,
		browser,
		h.codes[0],
		true,
		"",
	); err != nil {
		t.Fatal("rollback consumed recovery", err)
	}

	pending = h.begin(t, browser, totp.SignIn)

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = tx.Rollback(ctx) }()
	// Hold the exact account fence while another completion is in flight.
	if _, err := tx.Exec(
		ctx,
		"SELECT id FROM pluto_auth_accounts FOR UPDATE",
	); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)

	go func() {
		_, err := h.service.Finish(
			ctx,
			pending.Challenge,
			browser,
			h.codes[1],
			true,
			"",
		)
		done <- err
	}()

	if _, err := tx.Exec(
		ctx,
		"UPDATE pluto_auth_accounts SET disabled=true, credential_version=credential_version+1",
	); err != nil {
		t.Fatal(err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	if err := <-done; !errors.Is(err, totp.ErrDenied) {
		t.Fatal("disable fence bypass", err)
	}
}

func TestBrowserNativeWorkflow(t *testing.T) {
	h := setup(t)

	handler, err := totphttp.New(h.service, totphttp.Config{
		Transport: httpauth.Config{
			TrustedOrigins: []string{"https://app.example"},
		},
		Ingress: func(next http.Handler) http.Handler { return next },
		Primary: h.password.BeginSignIn,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := func(path, body, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(
			http.MethodPost,
			"https://app.example"+path,
			strings.NewReader(body),
		)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)

		if cookie != nil {
			req.AddCookie(cookie)
		}

		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)

		return response
	}

	input := `{"email":"alice@example.com","password":"long password test","action":"signin"}`
	if response := request(
		"/begin",
		input,
		"https://evil.example",
		nil,
	); response.Code != http.StatusForbidden {
		t.Fatal("Origin bypass")
	}

	response := request("/begin", input, "https://app.example", nil)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}

	var pending totp.Setup
	if err := json.Unmarshal(response.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}

	var browser *http.Cookie

	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == httpauth.CookieName {
			t.Fatal("session before completion")
		}

		if cookie.Name == totphttp.BrowserCookie {
			browser = cookie
		}
	}

	if browser == nil || !browser.Secure || !browser.HttpOnly ||
		browser.SameSite != http.SameSiteStrictMode {
		t.Fatal("browser cookie")
	}

	body, _ := json.Marshal(struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
		Recovery  bool   `json:"recovery"`
	}{pending.Challenge, h.codes[0], true})
	if response := request(
		"/finish",
		string(body),
		"https://app.example",
		nil,
	); response.Code != 401 {
		t.Fatal("missing browser")
	}

	response = request("/finish", string(body), "https://app.example", browser)
	if response.Code != 200 ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(response.Body.String())
	}

	found := false

	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == httpauth.CookieName {
			found = true
		}
	}

	if !found {
		t.Fatal("missing session cookie")
	}
}
