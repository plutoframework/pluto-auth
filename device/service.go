package device

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	auth "github.com/plutoframework/pluto-auth"
)

const (
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	userCodeLength   = 8
	maxScopes        = 32
)

// Service issues, rotates, verifies and revokes delegated-client tokens.
type Service struct {
	store    Store
	config   Config
	clients  map[string]Client
	sessions *auth.Manager
}

// New validates configuration and returns a service.
func New(store Store, config Config) (*Service, error) {
	if store == nil || config.Sessions == nil || config.Authorizer == nil ||
		config.Limiter == nil || len(config.Clients) == 0 {
		return nil, auth.ErrInvalidConfig
	}

	if config.Clock == nil {
		config.Clock = time.Now
	}

	defaults(&config.CodeTTL, 10*time.Minute)
	defaults(&config.PollInterval, 5*time.Second)
	defaults(&config.SlowDownStep, 5*time.Second)
	defaults(&config.AccessTTL, 15*time.Minute)
	defaults(&config.RefreshTTL, 30*24*time.Hour)
	defaults(&config.MaxLifetime, 90*24*time.Hour)

	parsed, err := url.Parse(config.VerificationURI)
	if err != nil || parsed.Host == "" || parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, auth.ErrInvalidConfig
	}

	clients := map[string]Client{}

	for _, client := range config.Clients {
		client.Scopes = normalizeScopes(client.Scopes)
		if client.ID == "" || client.Name == "" || client.ActorType == "" ||
			len(client.Scopes) == 0 || len(client.Scopes) > maxScopes {
			return nil, auth.ErrInvalidConfig
		}

		for _, scope := range client.Scopes {
			if !ValidScope(scope) {
				return nil, auth.ErrInvalidConfig
			}
		}

		if _, duplicate := clients[client.ID]; duplicate {
			return nil, auth.ErrInvalidConfig
		}

		clients[client.ID] = client
	}

	if config.AccessTTL > config.RefreshTTL ||
		config.RefreshTTL > config.MaxLifetime {
		return nil, auth.ErrInvalidConfig
	}

	return &Service{
		store:    store,
		config:   config,
		clients:  clients,
		sessions: config.Sessions,
	}, nil
}

func defaults(value *time.Duration, fallback time.Duration) {
	if *value <= 0 {
		*value = fallback
	}
}

func (s *Service) now() time.Time {
	return s.config.Clock().UTC()
}

// Code is the device authorization response (RFC 8628 section 3.2).
type Code struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Authorize starts a device request for a declared client. It is public and
// tenant-less; callers must bound it with ingress rate limiting.
func (s *Service) Authorize(
	ctx context.Context,
	clientID string,
	requested []string,
) (Code, error) {
	client, ok := s.clients[clientID]
	if !ok {
		return Code{}, ErrInvalidClient
	}

	scopes := normalizeScopes(requested)
	if len(scopes) == 0 {
		scopes = slices.Clone(client.Scopes)
	}

	for _, scope := range scopes {
		if !slices.Contains(client.Scopes, scope) {
			return Code{}, ErrInvalidScope
		}
	}

	now := s.now()

	for range 5 {
		deviceCode, err := randomToken()
		if err != nil {
			return Code{}, err
		}

		userCode, err := newUserCode()
		if err != nil {
			return Code{}, err
		}

		device, err := auth.TokenDigest(deviceCode)
		if err != nil {
			return Code{}, err
		}

		id, err := randomID()
		if err != nil {
			return Code{}, err
		}

		err = s.store.CreateAuthorization(ctx, Authorization{
			ID:        id,
			Device:    device,
			User:      userDigest(userCode),
			ClientID:  client.ID,
			Scopes:    scopes,
			CreatedAt: now,
			ExpiresAt: now.Add(s.config.CodeTTL),
			Interval:  s.config.PollInterval,
			State:     StatePending,
		})
		if errors.Is(err, ErrConflict) {
			continue
		}

		if err != nil {
			return Code{}, err
		}

		display := userCode[:4] + "-" + userCode[4:]
		complete := s.config.VerificationURI + "?user_code=" +
			url.QueryEscape(display)

		return Code{
			DeviceCode:              deviceCode,
			UserCode:                display,
			VerificationURI:         s.config.VerificationURI,
			VerificationURIComplete: complete,
			ExpiresIn:               int(s.config.CodeTTL / time.Second),
			Interval:                int(s.config.PollInterval / time.Second),
		}, nil
	}

	return Code{}, ErrConflict
}

// Request is what the owner sees before deciding.
type Request struct {
	ClientID   string
	ClientName string
	ActorType  string
	Scopes     []string
	ExpiresIn  int
}

// Lookup describes a pending request to its (authenticated) owner.
func (s *Service) Lookup(
	ctx context.Context,
	identity *auth.Identity,
	userCode string,
) (Request, error) {
	authorization, _, err := s.pending(ctx, identity, userCode)
	if err != nil {
		return Request{}, err
	}

	client := s.clients[authorization.ClientID]

	return Request{
		ClientID:   client.ID,
		ClientName: client.Name,
		ActorType:  client.ActorType,
		Scopes:     authorization.Scopes,
		ExpiresIn: int(
			authorization.ExpiresAt.Sub(s.now()) / time.Second),
	}, nil
}

func (s *Service) pending(
	ctx context.Context,
	identity *auth.Identity,
	userCode string,
) (Authorization, string, error) {
	subject, err := s.subject(ctx, identity)
	if err != nil {
		return Authorization{}, "", err
	}

	digest, ok := parseUserCode(userCode)
	if !ok {
		return Authorization{}, "", ErrInvalidGrant
	}

	authorization, err := s.store.FindAuthorization(ctx, digest, s.now())
	if err != nil || authorization.State != StatePending {
		return Authorization{}, "", ErrInvalidGrant
	}

	return authorization, subject, nil
}

// subject verifies a live interactive identity. A delegated token can never
// approve, deny or manage grants: a delegate must not widen itself.
func (s *Service) subject(
	ctx context.Context,
	identity *auth.Identity,
) (string, error) {
	if ctx == nil || identity == nil {
		return "", auth.ErrUnauthenticated
	}

	if _, delegated := identity.Delegation(); delegated {
		return "", ErrForbidden
	}

	var subject string

	err := s.sessions.UseIdentity(
		ctx,
		identity,
		func(_ context.Context, id string) error {
			subject = id

			return nil
		},
	)
	if err != nil {
		return "", auth.ErrUnauthenticated
	}

	if err := s.config.Limiter.Allow(ctx, "device:"+subject); err != nil {
		return "", ErrRateLimited
	}

	return subject, nil
}

// Approve records the owner's approval of a subset of the requested scopes in
// one tenant. The subject comes only from the verified identity.
func (s *Service) Approve(
	ctx context.Context,
	identity *auth.Identity,
	userCode, tenant string,
	scopes []string,
) error {
	authorization, subject, err := s.pending(ctx, identity, userCode)
	if err != nil {
		return err
	}

	approved := normalizeScopes(scopes)
	if tenant == "" || len(approved) == 0 {
		return ErrInvalidRequest
	}

	for _, scope := range approved {
		if !slices.Contains(authorization.Scopes, scope) {
			return ErrInvalidScope
		}
	}

	if err := s.config.Authorizer.AuthorizeDelegation(
		ctx, subject, tenant, approved); err != nil {
		return ErrForbidden
	}

	return s.decide(ctx, authorization, Decision{
		Approve: true,
		Subject: subject,
		Tenant:  tenant,
		Scopes:  approved,
	})
}

// Deny rejects a pending request.
func (s *Service) Deny(
	ctx context.Context,
	identity *auth.Identity,
	userCode string,
) error {
	authorization, subject, err := s.pending(ctx, identity, userCode)
	if err != nil {
		return err
	}

	return s.decide(ctx, authorization, Decision{Subject: subject})
}

func (s *Service) decide(
	ctx context.Context,
	authorization Authorization,
	decision Decision,
) error {
	err := s.store.Decide(ctx, authorization.User, s.now(), decision)

	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrScope):
		return ErrInvalidScope
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrExpired):
		return ErrInvalidGrant
	}

	return err
}

// TokenRequest is the parsed token endpoint input.
type TokenRequest struct {
	GrantType    string
	ClientID     string
	DeviceCode   string
	RefreshToken string
	Scopes       []string
}

// TokenResponse is the RFC 6749 section 5.1 response. Tokens are returned
// once and never stored in plaintext.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	Tenant       string `json:"tenant"`
	GrantID      string `json:"grant_id"`
}

// Token serves the token endpoint for the device-code and refresh grants.
// Polling faster than the interval yields slow_down and raises the interval.
func (s *Service) Token(
	ctx context.Context,
	request TokenRequest,
) (TokenResponse, error) {
	if _, ok := s.clients[request.ClientID]; !ok {
		return TokenResponse{}, ErrInvalidClient
	}

	switch request.GrantType {
	case GrantDeviceCode:
		return s.redeem(ctx, request)
	case GrantRefreshToken:
		return s.refresh(ctx, request)
	}

	return TokenResponse{}, ErrUnsupportedGrant
}

type material struct {
	access, refresh       string
	accessID              string
	accessDigest          auth.Digest
	refreshDigest         auth.Digest
	accessTTL, refreshTTL time.Time
}

func (s *Service) material(now time.Time) (material, error) {
	var (
		m   material
		err error
	)

	if m.access, err = randomToken(); err != nil {
		return m, err
	}

	if m.refresh, err = randomToken(); err != nil {
		return m, err
	}

	if m.accessID, err = randomID(); err != nil {
		return m, err
	}

	if m.accessDigest, err = auth.TokenDigest(m.access); err != nil {
		return m, err
	}

	if m.refreshDigest, err = auth.TokenDigest(m.refresh); err != nil {
		return m, err
	}

	m.accessTTL = now.Add(s.config.AccessTTL)
	m.refreshTTL = now.Add(s.config.RefreshTTL)

	return m, nil
}

func (s *Service) redeem(
	ctx context.Context,
	request TokenRequest,
) (TokenResponse, error) {
	device, err := auth.TokenDigest(request.DeviceCode)
	if err != nil {
		return TokenResponse{}, ErrInvalidGrant
	}

	now := s.now()

	issued, err := s.material(now)
	if err != nil {
		return TokenResponse{}, err
	}

	grantID, err := randomID()
	if err != nil {
		return TokenResponse{}, err
	}

	client := s.clients[request.ClientID]

	result, err := s.store.Poll(ctx, device, now, Redemption{
		ClientID:       client.ID,
		Step:           s.config.SlowDownStep,
		GrantID:        grantID,
		ActorType:      client.ActorType,
		AccessID:       issued.accessID,
		Access:         issued.accessDigest,
		AccessExpires:  issued.accessTTL,
		Refresh:        issued.refreshDigest,
		RefreshExpires: issued.refreshTTL,
		MaxLifetime:    s.config.MaxLifetime,
	})

	switch {
	case errors.Is(err, ErrExpired):
		return TokenResponse{}, ErrExpiredToken
	case errors.Is(err, ErrNotFound):
		return TokenResponse{}, ErrInvalidGrant
	case err != nil:
		return TokenResponse{}, err
	}

	switch result.State {
	case PollPending:
		return TokenResponse{}, ErrAuthorizationPending
	case PollSlowDown:
		return TokenResponse{}, ErrSlowDown
	case PollDenied:
		return TokenResponse{}, ErrAccessDenied
	case PollIssued:
		return s.response(issued, result.Grant, now), nil
	}

	return TokenResponse{}, ErrInvalidRequest
}

func (s *Service) refresh(
	ctx context.Context,
	request TokenRequest,
) (TokenResponse, error) {
	presented, err := auth.TokenDigest(request.RefreshToken)
	if err != nil {
		return TokenResponse{}, ErrInvalidGrant
	}

	now := s.now()

	issued, err := s.material(now)
	if err != nil {
		return TokenResponse{}, err
	}

	grant, err := s.store.Rotate(ctx, presented, now, Rotation{
		ClientID:       request.ClientID,
		Narrow:         normalizeScopes(request.Scopes),
		AccessID:       issued.accessID,
		Access:         issued.accessDigest,
		AccessExpires:  issued.accessTTL,
		Refresh:        issued.refreshDigest,
		RefreshExpires: issued.refreshTTL,
	})

	switch {
	case errors.Is(err, ErrScope):
		return TokenResponse{}, ErrInvalidScope
	case errors.Is(err, ErrReuse), errors.Is(err, ErrNotFound),
		errors.Is(err, ErrExpired):
		return TokenResponse{}, ErrInvalidGrant
	case err != nil:
		return TokenResponse{}, err
	}

	return s.response(issued, grant, now), nil
}

func (s *Service) response(
	issued material,
	grant Grant,
	now time.Time,
) TokenResponse {
	return TokenResponse{
		AccessToken:  issued.access,
		TokenType:    "Bearer",
		ExpiresIn:    int(issued.accessTTL.Sub(now) / time.Second),
		RefreshToken: issued.refresh,
		Scope:        strings.Join(grant.Scopes, " "),
		Tenant:       grant.Tenant,
		GrantID:      grant.ID,
	}
}

// Session verifies an access token digest. Wrap a session store with it so
// delegated tokens authenticate through the ordinary Manager and Identity: the
// returned session carries the Delegation. The reference is never extended.
func (s *Service) Session(
	ctx context.Context,
	digest auth.Digest,
	now time.Time,
) (auth.Session, error) {
	grant, token, err := s.store.Access(ctx, digest, now)
	if err != nil {
		return auth.Session{}, auth.ErrNotFound
	}

	if !grant.Active(now) || !now.Before(token.ExpiresAt) {
		return auth.Session{}, auth.ErrNotFound
	}

	return auth.Session{
		ID:         token.ID,
		SubjectID:  grant.Subject,
		CreatedAt:  grant.CreatedAt,
		ExpiresAt:  token.ExpiresAt,
		LastSeenAt: now,
		Delegation: grant.Delegation(),
	}, nil
}

// Revoke implements RFC 7009: possession of an access or refresh token revokes
// its whole family. Unknown tokens succeed silently.
func (s *Service) Revoke(ctx context.Context, token string) error {
	digest, err := auth.TokenDigest(token)
	if err != nil {
		return nil
	}

	return s.store.RevokeToken(ctx, digest)
}

// RevokeDigest revokes the family of an access token digest (session logout).
func (s *Service) RevokeDigest(ctx context.Context, digest auth.Digest) error {
	return s.store.RevokeToken(ctx, digest)
}

// RevokeSubject revokes every family of a subject.
func (s *Service) RevokeSubject(ctx context.Context, subject string) error {
	return s.store.RevokeSubject(ctx, subject)
}

// Grants lists the caller's active families.
func (s *Service) Grants(
	ctx context.Context,
	identity *auth.Identity,
) ([]Grant, error) {
	subject, err := s.subject(ctx, identity)
	if err != nil {
		return nil, err
	}

	return s.store.ListGrants(ctx, subject, s.now())
}

// RevokeGrant revokes one of the caller's own families.
func (s *Service) RevokeGrant(
	ctx context.Context,
	identity *auth.Identity,
	id string,
) error {
	subject, err := s.subject(ctx, identity)
	if err != nil {
		return err
	}

	if err := s.store.RevokeGrant(ctx, subject, id); err != nil {
		return ErrInvalidGrant
	}

	return nil
}

// ClientByID returns a declared client.
func (s *Service) ClientByID(id string) (Client, bool) {
	client, ok := s.clients[id]

	return client, ok
}

func normalizeScopes(scopes []string) []string {
	out := slices.Clone(scopes)
	sort.Strings(out)

	return slices.Compact(out)
}

func randomToken() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(secret), nil
}

func randomID() (string, error) {
	return rand.Text(), nil
}

func newUserCode() (string, error) {
	code := make([]byte, 0, userCodeLength)
	limit := byte(256 - 256%len(userCodeAlphabet))

	for len(code) < userCodeLength {
		buffer := make([]byte, 16)
		if _, err := rand.Read(buffer); err != nil {
			return "", err
		}

		for _, b := range buffer {
			if b < limit && len(code) < userCodeLength {
				code = append(
					code,
					userCodeAlphabet[int(b)%len(userCodeAlphabet)],
				)
			}
		}
	}

	return string(code), nil
}

// parseUserCode accepts only well formed codes and returns their digest.
func parseUserCode(input string) (auth.Digest, bool) {
	code := strings.ToUpper(
		strings.NewReplacer("-", "", " ", "").Replace(input),
	)
	if len(code) != userCodeLength {
		return auth.Digest{}, false
	}

	for _, r := range code {
		if !strings.ContainsRune(userCodeAlphabet, r) {
			return auth.Digest{}, false
		}
	}

	return userDigest(code), true
}

func userDigest(code string) auth.Digest {
	return sha256.Sum256([]byte("pluto-device-user-code\x00" + code))
}

// SameDigest compares digests in constant time.
func SameDigest(a, b auth.Digest) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
