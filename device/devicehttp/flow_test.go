package devicehttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/device"
	"github.com/plutoframework/pluto-auth/device/devicehttp"
	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

const origin = "https://app.example.test"

type clock struct {
	mutex sync.Mutex
	now   time.Time
}

func (c *clock) Now() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.now = c.now.Add(d)
}

type authorizer struct{ allowed map[string]bool }

func (a authorizer) AuthorizeDelegation(
	_ context.Context,
	subject, tenant string,
	_ []string,
) error {
	if a.allowed[subject+"@"+tenant] {
		return nil
	}

	return errors.New("not a member")
}

type limiter struct {
	mutex sync.Mutex
	count map[string]int
	max   int
}

func (l *limiter) Allow(_ context.Context, key string) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.count[key]++
	if l.count[key] > l.max {
		return errors.New("limited")
	}

	return nil
}

type rig struct {
	t        *testing.T
	clock    *clock
	manager  *auth.Manager
	service  *device.Service
	handler  http.Handler
	store    *memory.DeviceStore
	limiter  *limiter
	deviceDB *memory.Store
}

type overlay struct {
	auth.SessionStore
	service *device.Service
}

func (o overlay) Use(
	ctx context.Context,
	digest auth.Digest,
	now time.Time,
	idle time.Duration,
) (auth.Session, error) {
	session, err := o.SessionStore.Use(ctx, digest, now, idle)
	if errors.Is(err, auth.ErrNotFound) {
		return o.service.Session(ctx, digest, now)
	}

	return session, err
}

func (o overlay) Delete(ctx context.Context, digest auth.Digest) error {
	if err := o.service.RevokeDigest(ctx, digest); err != nil {
		return err
	}

	return o.SessionStore.Delete(ctx, digest)
}

func newRig(t *testing.T) *rig {
	t.Helper()

	clock := &clock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}

	sessions, err := memory.New(100)
	if err != nil {
		t.Fatal(err)
	}

	config := auth.DefaultConfig()
	config.Clock = clock.Now

	// The overlay needs the service, which needs the manager: build the
	// manager over a late-bound store.
	late := &lateStore{}

	manager, err := auth.New(late, config)
	if err != nil {
		t.Fatal(err)
	}

	store := memory.NewDeviceStore()
	limit := &limiter{count: map[string]int{}, max: 1000}

	service, err := device.New(store, device.Config{
		Clients: []device.Client{{
			ID:        "cli",
			Name:      "Example CLI",
			ActorType: "agent",
			Scopes:    []string{"requests.write", "requests.read"},
		}, {
			ID:        "other",
			Name:      "Other CLI",
			ActorType: "agent",
			Scopes:    []string{"requests.read"},
		}},
		Sessions: manager,
		Authorizer: authorizer{allowed: map[string]bool{
			"alice@acme": true,
		}},
		Limiter:         limit,
		VerificationURI: origin + "/device",
		Clock:           clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}

	late.SessionStore = overlay{SessionStore: sessions, service: service}

	transport, err := httpauth.New(manager, httpauth.Config{
		TrustedOrigins: []string{origin},
		AllowBearer:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	handler, err := devicehttp.New(service, devicehttp.Config{
		Transport: transport,
		Ingress:   func(next http.Handler) http.Handler { return next },
	})
	if err != nil {
		t.Fatal(err)
	}

	return &rig{
		t: t, clock: clock, manager: manager, service: service,
		handler: handler, store: store, limiter: limit, deviceDB: sessions,
	}
}

type lateStore struct{ auth.SessionStore }

func (r *rig) login(subject string) string {
	issued, err := r.manager.Start(context.Background(), subject)
	if err != nil {
		r.t.Fatal(err)
	}

	return issued.Token
}

func (r *rig) do(
	method, path, token string,
	body map[string]any,
) (*httptest.ResponseRecorder, map[string]any) {
	r.t.Helper()

	encoded, _ := json.Marshal(body)
	request := httptest.NewRequest(
		method,
		path,
		strings.NewReader(string(encoded)),
	)
	request.Header.Set("Content-Type", "application/json")

	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Origin", origin)
	}

	recorder := httptest.NewRecorder()
	r.handler.ServeHTTP(recorder, request)

	var out map[string]any

	_ = json.Unmarshal(recorder.Body.Bytes(), &out)

	return recorder, out
}

func (r *rig) start(scope string) map[string]any {
	r.t.Helper()

	recorder, out := r.do("POST", "/code", "", map[string]any{
		"client_id": "cli", "scope": scope,
	})
	if recorder.Code != 200 {
		r.t.Fatalf("code: %d %v", recorder.Code, out)
	}

	return out
}

func (r *rig) poll(code string) (int, map[string]any) {
	recorder, out := r.do("POST", "/token", "", map[string]any{
		"grant_type":  device.GrantDeviceCode,
		"client_id":   "cli",
		"device_code": code,
	})

	return recorder.Code, out
}

// approved runs the whole flow and returns the token response.
func (r *rig) approved(scope string) map[string]any {
	r.t.Helper()

	started := r.start("requests.write requests.read")
	owner := r.login("alice")

	recorder, out := r.do("POST", "/approve", owner, map[string]any{
		"user_code": started["user_code"], "tenant": "acme", "scope": scope,
	})
	if recorder.Code != 204 {
		r.t.Fatalf("approve: %d %v", recorder.Code, out)
	}

	r.clock.advance(6 * time.Second)

	status, tokens := r.poll(started["device_code"].(string))
	if status != 200 {
		r.t.Fatalf("token: %d %v", status, tokens)
	}

	return tokens
}

func TestFullDeviceFlow(t *testing.T) {
	r := newRig(t)

	started := r.start("")
	if started["verification_uri"] != origin+"/device" ||
		!strings.HasPrefix(started["verification_uri_complete"].(string),
			origin+"/device?user_code=") ||
		started["interval"].(float64) != 5 {
		t.Fatalf("unexpected response %v", started)
	}

	// Pending until the owner decides, and a lookup shows what is asked.
	r.clock.advance(6 * time.Second)

	if status, out := r.poll(started["device_code"].(string)); status != 400 ||
		out["error"] != "authorization_pending" {
		t.Fatalf("expected pending, got %d %v", status, out)
	}

	owner := r.login("alice")

	recorder, out := r.do("GET", "/request?user_code="+
		url.QueryEscape(started["user_code"].(string)), owner, nil)
	if recorder.Code != 200 || out["client_name"] != "Example CLI" ||
		out["actor_type"] != "agent" {
		t.Fatalf("lookup: %d %v", recorder.Code, out)
	}

	recorder, out = r.do("POST", "/approve", owner, map[string]any{
		"user_code": started["user_code"], "tenant": "acme",
		"scope": "requests.write",
	})
	if recorder.Code != 204 {
		t.Fatalf("approve: %d %v", recorder.Code, out)
	}

	r.clock.advance(6 * time.Second)

	status, tokens := r.poll(started["device_code"].(string))
	if status != 200 || tokens["token_type"] != "Bearer" ||
		tokens["scope"] != "requests.write" || tokens["tenant"] != "acme" ||
		tokens["expires_in"].(float64) != 900 {
		t.Fatalf("token: %d %v", status, tokens)
	}

	// The code is single use.
	r.clock.advance(6 * time.Second)

	if status, out := r.poll(started["device_code"].(string)); status != 400 ||
		out["error"] != "invalid_grant" {
		t.Fatalf("code reuse: %d %v", status, out)
	}

	// The access token is an ordinary identity carrying the delegation.
	err := r.manager.WithIdentity(
		context.Background(),
		tokens["access_token"].(string),
		func(ctx context.Context, identity *auth.Identity) error {
			delegation, ok := identity.Delegation()
			if !ok || delegation.ClientID != "cli" ||
				delegation.ActorType != "agent" ||
				delegation.Tenant != "acme" ||
				len(delegation.Scopes) != 1 ||
				delegation.Scopes[0] != "requests.write" {
				t.Fatalf("delegation %+v %v", delegation, ok)
			}

			return r.manager.UseIdentity(ctx, identity,
				func(_ context.Context, subject string) error {
					if subject != "alice" {
						t.Fatalf("subject %q", subject)
					}

					return nil
				})
		})
	if err != nil {
		t.Fatal(err)
	}

	// A browser session has no delegation.
	err = r.manager.WithIdentity(context.Background(), owner,
		func(_ context.Context, identity *auth.Identity) error {
			if _, ok := identity.Delegation(); ok {
				t.Fatal("interactive session must not be delegated")
			}

			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
}

func TestApprovalNarrowsAndNeverWidens(t *testing.T) {
	r := newRig(t)
	started := r.start("requests.read")
	owner := r.login("alice")

	for name, body := range map[string]map[string]any{
		"widen scope":   {"scope": "requests.write", "tenant": "acme"},
		"unknown scope": {"scope": "admin", "tenant": "acme"},
		"no scope":      {"tenant": "acme"},
		"not a member":  {"scope": "requests.read", "tenant": "other"},
		"no tenant":     {"scope": "requests.read"},
	} {
		body["user_code"] = started["user_code"]

		if recorder, _ := r.do(
			"POST",
			"/approve",
			owner,
			body,
		); recorder.Code < 400 {
			t.Fatalf("%s: accepted with %d", name, recorder.Code)
		}
	}

	// The request itself cannot exceed the client's declared scopes.
	if recorder, _ := r.do("POST", "/code", "", map[string]any{
		"client_id": "cli", "scope": "admin",
	}); recorder.Code != 400 {
		t.Fatalf("undeclared scope: %d", recorder.Code)
	}

	if recorder, _ := r.do("POST", "/code", "", map[string]any{
		"client_id": "nobody",
	}); recorder.Code != 401 {
		t.Fatalf("unknown client: %d", recorder.Code)
	}
}

func TestPollingIsRateLimited(t *testing.T) {
	r := newRig(t)
	started := r.start("")
	code := started["device_code"].(string)

	r.clock.advance(6 * time.Second)

	if _, out := r.poll(code); out["error"] != "authorization_pending" {
		t.Fatalf("first poll %v", out)
	}

	// Immediately again: slow_down, and the interval grows by 5 seconds.
	status, out := r.poll(code)
	if status != 400 || out["error"] != "slow_down" {
		t.Fatalf("expected slow_down, got %d %v", status, out)
	}

	// The old interval is no longer enough.
	r.clock.advance(6 * time.Second)

	if _, out := r.poll(code); out["error"] != "slow_down" {
		t.Fatalf("interval must have grown: %v", out)
	}

	r.clock.advance(16 * time.Second)

	if _, out := r.poll(code); out["error"] != "authorization_pending" {
		t.Fatalf("poll after the new interval: %v", out)
	}
}

func TestDenyAndExpiry(t *testing.T) {
	r := newRig(t)
	owner := r.login("alice")

	denied := r.start("")
	if recorder, _ := r.do("POST", "/deny", owner, map[string]any{
		"user_code": denied["user_code"],
	}); recorder.Code != 204 {
		t.Fatalf("deny: %d", recorder.Code)
	}

	r.clock.advance(6 * time.Second)

	if _, out := r.poll(
		denied["device_code"].(string),
	); out["error"] != "access_denied" {
		t.Fatalf("expected access_denied, got %v", out)
	}

	expired := r.start("")
	r.clock.advance(11 * time.Minute)

	if _, out := r.poll(
		expired["device_code"].(string),
	); out["error"] != "expired_token" {
		t.Fatalf("expected expired_token, got %v", out)
	}

	if recorder, _ := r.do("POST", "/approve", owner, map[string]any{
		"user_code": expired["user_code"],
		"tenant":    "acme",
		"scope":     "requests.read",
	}); recorder.Code != 400 {
		t.Fatalf("approving an expired code: %d", recorder.Code)
	}
}

func TestClientBinding(t *testing.T) {
	r := newRig(t)
	started := r.start("")

	recorder, out := r.do("POST", "/token", "", map[string]any{
		"grant_type": device.GrantDeviceCode, "client_id": "nobody",
		"device_code": started["device_code"],
	})
	if recorder.Code != 401 || out["error"] != "invalid_client" {
		t.Fatalf("%d %v", recorder.Code, out)
	}

	// A code is bound to the client that started it.
	recorder, out = r.do("POST", "/token", "", map[string]any{
		"grant_type": device.GrantDeviceCode, "client_id": "other",
		"device_code": started["device_code"],
	})
	if recorder.Code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("foreign client: %d %v", recorder.Code, out)
	}

	if recorder, _ := r.do("POST", "/token", "", map[string]any{
		"grant_type": device.GrantDeviceCode, "client_id": "cli",
		"device_code": "not-a-code",
	}); recorder.Code != 400 {
		t.Fatalf("malformed code: %d", recorder.Code)
	}

	if recorder, _ := r.do("POST", "/token", "", map[string]any{
		"grant_type": "password", "client_id": "cli",
	}); recorder.Code != 400 {
		t.Fatalf("unsupported grant: %d", recorder.Code)
	}
}

func (r *rig) authenticates(token string) bool {
	_, err := r.manager.Authenticate(context.Background(), token)

	return err == nil
}

func (r *rig) refresh(token string, scope string) (int, map[string]any) {
	body := map[string]any{
		"grant_type": device.GrantRefreshToken, "client_id": "cli",
		"refresh_token": token,
	}
	if scope != "" {
		body["scope"] = scope
	}

	recorder, out := r.do("POST", "/token", "", body)

	return recorder.Code, out
}

func TestRefreshRotationAndReuseRevokesFamily(t *testing.T) {
	r := newRig(t)
	first := r.approved("requests.write requests.read")

	r.clock.advance(time.Minute)

	status, second := r.refresh(first["refresh_token"].(string), "")
	if status != 200 || second["refresh_token"] == first["refresh_token"] ||
		second["access_token"] == first["access_token"] {
		t.Fatalf("refresh: %d %v", status, second)
	}

	// Rotation revokes the previous access token immediately.
	if r.authenticates(first["access_token"].(string)) {
		t.Fatal("rotated access token still valid")
	}

	if !r.authenticates(second["access_token"].(string)) {
		t.Fatal("fresh access token rejected")
	}

	status, third := r.refresh(second["refresh_token"].(string), "")
	if status != 200 {
		t.Fatalf("second rotation: %d %v", status, third)
	}

	// Replaying an already rotated refresh token is theft evidence: the whole
	// family dies, including the newest valid tokens.
	status, out := r.refresh(first["refresh_token"].(string), "")
	if status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("reuse: %d %v", status, out)
	}

	if r.authenticates(third["access_token"].(string)) {
		t.Fatal("family survived reuse detection")
	}

	if status, _ := r.refresh(
		third["refresh_token"].(string),
		"",
	); status != 400 {
		t.Fatal("newest refresh token survived reuse detection")
	}
}

func TestRefreshNarrowsButNeverWidens(t *testing.T) {
	r := newRig(t)
	first := r.approved("requests.read")

	if status, out := r.refresh(first["refresh_token"].(string),
		"requests.read requests.write"); status != 400 ||
		out["error"] != "invalid_scope" {
		t.Fatalf("widening refresh: %d %v", status, out)
	}

	// A rejected widening does not consume or burn the token.
	status, narrowed := r.refresh(
		first["refresh_token"].(string),
		"requests.read",
	)
	if status != 200 || narrowed["scope"] != "requests.read" {
		t.Fatalf("narrowing refresh: %d %v", status, narrowed)
	}
}

func TestRefreshExpiry(t *testing.T) {
	r := newRig(t)
	first := r.approved("requests.read")

	r.clock.advance(15 * time.Minute)

	if r.authenticates(first["access_token"].(string)) {
		t.Fatal("expired access token accepted")
	}

	r.clock.advance(31 * 24 * time.Hour)

	if status, _ := r.refresh(
		first["refresh_token"].(string),
		"",
	); status != 400 {
		t.Fatal("expired refresh token accepted")
	}
}

func TestRevocation(t *testing.T) {
	r := newRig(t)
	tokens := r.approved("requests.read")
	access := tokens["access_token"].(string)

	if !r.authenticates(access) {
		t.Fatal("token rejected before revocation")
	}

	// RFC 7009: revoking the refresh token kills the family.
	if recorder, _ := r.do("POST", "/revoke", "", map[string]any{
		"token": tokens["refresh_token"],
	}); recorder.Code != 200 {
		t.Fatalf("revoke: %d", recorder.Code)
	}

	if r.authenticates(access) {
		t.Fatal("revoked access token accepted")
	}

	if status, _ := r.refresh(
		tokens["refresh_token"].(string),
		"",
	); status != 400 {
		t.Fatal("revoked refresh token accepted")
	}

	// Unknown tokens are not an error and reveal nothing.
	if recorder, _ := r.do("POST", "/revoke", "", map[string]any{
		"token": "garbage",
	}); recorder.Code != 200 {
		t.Fatalf("unknown token: %d", recorder.Code)
	}
}

func TestOwnerManagesGrants(t *testing.T) {
	r := newRig(t)
	tokens := r.approved("requests.read")
	owner := r.login("alice")

	recorder, out := r.do("GET", "/grants", owner, nil)
	data, _ := out["data"].([]any)

	if recorder.Code != 200 || len(data) != 1 {
		t.Fatalf("grants: %d %v", recorder.Code, out)
	}

	// Another subject cannot revoke it.
	other := r.login("mallory")
	grant := data[0].(map[string]any)["id"].(string)

	if recorder, _ := r.do(
		"DELETE",
		"/grants/"+grant,
		other,
		nil,
	); recorder.Code == 204 {
		t.Fatal("foreign subject revoked a grant")
	}

	if !r.authenticates(tokens["access_token"].(string)) {
		t.Fatal("grant revoked by a foreign subject")
	}

	if recorder, _ := r.do(
		"DELETE",
		"/grants/"+grant,
		owner,
		nil,
	); recorder.Code != 204 {
		t.Fatalf("owner revoke: %d", recorder.Code)
	}

	if r.authenticates(tokens["access_token"].(string)) {
		t.Fatal("grant survived owner revocation")
	}
}

func TestDelegateCannotApproveOrManage(t *testing.T) {
	r := newRig(t)
	tokens := r.approved("requests.read requests.write")
	access := tokens["access_token"].(string)

	other := r.start("requests.read")

	for _, call := range []struct {
		method, path string
		body         map[string]any
	}{
		{"POST", "/approve", map[string]any{
			"user_code": other["user_code"], "tenant": "acme",
			"scope": "requests.read",
		}},
		{"POST", "/deny", map[string]any{"user_code": other["user_code"]}},
		{"GET", "/grants", nil},
		{"GET", "/request?user_code=" + url.QueryEscape(
			other["user_code"].(string)), nil},
	} {
		recorder, _ := r.do(call.method, call.path, access, call.body)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("%s %s by a delegate: %d", call.method, call.path,
				recorder.Code)
		}
	}
}

func TestApproveNeedsTrustedOriginAndSession(t *testing.T) {
	r := newRig(t)
	started := r.start("")
	body := map[string]any{
		"user_code": started["user_code"],
		"tenant":    "acme",
		"scope":     "requests.read",
	}

	if recorder, _ := r.do(
		"POST",
		"/approve",
		"",
		body,
	); recorder.Code != 403 &&
		recorder.Code != 401 {
		t.Fatalf("anonymous approve: %d", recorder.Code)
	}

	encoded, _ := json.Marshal(body)
	request := httptest.NewRequest(
		"POST",
		"/approve",
		strings.NewReader(string(encoded)),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+r.login("alice"))
	request.Header.Set("Origin", "https://evil.example.test")

	recorder := httptest.NewRecorder()
	r.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("untrusted origin: %d", recorder.Code)
	}
}

func TestOwnerLookupsAreRateLimited(t *testing.T) {
	r := newRig(t)
	r.limiter.max = 3
	owner := r.login("alice")

	var limited bool

	for range 6 {
		recorder, _ := r.do("GET", "/request?user_code=BCDF-GHJK", owner, nil)
		if recorder.Code == http.StatusTooManyRequests {
			limited = true
		}
	}

	if !limited {
		t.Fatal("user-code guessing was not rate limited")
	}
}

func TestSubjectRevocationRevokesDelegates(t *testing.T) {
	r := newRig(t)
	tokens := r.approved("requests.read")

	if err := r.manager.RevokeSubject(
		context.Background(),
		"alice",
	); err != nil {
		t.Fatal(err)
	}

	// RevokeSubject on a Manager reaches the store; the overlay in this rig
	// leaves delegated families to the explicit service call.
	if err := r.service.RevokeSubject(
		context.Background(),
		"alice",
	); err != nil {
		t.Fatal(err)
	}

	if r.authenticates(tokens["access_token"].(string)) {
		t.Fatal("delegate survived subject revocation")
	}
}

func TestFormEncodedAndDuplicateParameters(t *testing.T) {
	r := newRig(t)

	form := url.Values{"client_id": {"cli"}}
	request := httptest.NewRequest(
		"POST",
		"/code",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	r.handler.ServeHTTP(recorder, request)

	if recorder.Code != 200 {
		t.Fatalf("form request: %d %s", recorder.Code, recorder.Body)
	}

	request = httptest.NewRequest("POST", "/code",
		strings.NewReader("client_id=cli&client_id=cli"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder = httptest.NewRecorder()
	r.handler.ServeHTTP(recorder, request)

	if recorder.Code != 400 {
		t.Fatalf("duplicate parameter: %d", recorder.Code)
	}
}
