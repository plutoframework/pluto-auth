// Package oidc implements the protocol boundary for OpenID Connect code login.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"time"

	protocol "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrConfig = errors.New("oidc: invalid configuration")
	ErrDenied = errors.New("oidc: authentication denied")
)

// Transaction contains secrets. Persist encrypted server-side; never serialize
// it into a cookie, browser response, diagnostic or log.
type Transaction struct {
	State         string
	BrowserDigest [32]byte
	Nonce         string
	Verifier      string
	Expires       time.Time
}

// Transactions must enforce bounded capacity, expiration and atomic consumption.
// Consume must match state, browser digest and now < expiry before deleting.
// A mismatch must not delete another browser's pending transaction.
type Transactions interface {
	Save(context.Context, Transaction) error
	Consume(context.Context, string, [32]byte, time.Time) (Transaction, error)
}

type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	HTTPClient   *http.Client
	Transactions Transactions
	Clock        func() time.Time
	Lifetime     time.Duration
}

type Client struct {
	issuer       string
	oauth        oauth2.Config
	verifier     *protocol.IDTokenVerifier
	http         *http.Client
	transactions Transactions
	clock        func() time.Time
	lifetime     time.Duration
}

// Identity is verified protocol identity only. It grants no local account,
// membership, role or linking authority. Resolve using issuer + subject only.
type Identity struct {
	issuer  string
	subject string
}

func (i Identity) Issuer() string  { return i.issuer }
func (i Identity) Subject() string { return i.subject }

func secureURL(raw string) bool {
	u, err := url.Parse(raw)

	return err == nil && u.Scheme == "https" && u.Hostname() != "" &&
		u.User == nil && u.Fragment == "" && u.RawQuery == ""
}

func New(ctx context.Context, config Config) (*Client, error) {
	if !secureURL(config.Issuer) || !secureURL(config.RedirectURL) ||
		config.ClientID == "" || config.ClientSecret == "" ||
		config.Transactions == nil {
		return nil, ErrConfig
	}

	if config.Lifetime == 0 {
		config.Lifetime = 5 * time.Minute
	}

	if config.Lifetime <= 0 || config.Lifetime > 10*time.Minute {
		return nil, ErrConfig
	}

	if config.Clock == nil {
		config.Clock = time.Now
	}

	client := http.Client{Timeout: 15 * time.Second}
	if config.HTTPClient != nil {
		client = *config.HTTPClient
	}

	if client.Timeout <= 0 || client.Timeout > 30*time.Second {
		return nil, ErrConfig
	}

	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client.Transport = boundedTransport{base: client.Transport}
	ctx = protocol.ClientContext(ctx, &client)

	provider, err := protocol.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, ErrConfig
	}

	endpoint := provider.Endpoint()

	// One explicit authentication style prevents automatic code-exchange retry.
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	if !secureURL(endpoint.AuthURL) || !secureURL(endpoint.TokenURL) {
		return nil, ErrConfig
	}

	// Validate the discovered key endpoint as well as each actual HTTP request.
	var discovery struct {
		JWKS string `json:"jwks_uri"`
	}
	if provider.Claims(&discovery) != nil || !secureURL(discovery.JWKS) {
		return nil, ErrConfig
	}

	return &Client{
		issuer: config.Issuer,
		oauth: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret, RedirectURL: config.RedirectURL,
			Endpoint: endpoint, Scopes: []string{protocol.ScopeOpenID},
		},
		verifier: provider.VerifierContext(ctx, &protocol.Config{
			ClientID: config.ClientID, SupportedSigningAlgs: []string{"RS256"},
			Now: config.Clock,
		}),
		http: &client, transactions: config.Transactions,
		clock: config.Clock, lifetime: config.Lifetime,
	}, nil
}

func random() string {
	var bytes [32]byte
	// crypto/rand.Read terminates the process if system entropy fails.
	_, _ = rand.Read(bytes[:])

	return base64.RawURLEncoding.EncodeToString(bytes[:])
}

// Begin returns a provider URL. browserBinding must be a server-generated,
// high-entropy value held in a Secure, HttpOnly, SameSite=Lax cookie by the host.
// The host must rate-limit begin/callback and bound concurrent pending logins.
func (c *Client) Begin(
	ctx context.Context,
	browserBinding string,
) (string, error) {
	if len(browserBinding) < 32 || len(browserBinding) > 256 {
		return "", ErrDenied
	}

	tx := Transaction{
		State: random(), Nonce: random(), Verifier: oauth2.GenerateVerifier(),
		BrowserDigest: sha256.Sum256([]byte(browserBinding)),
		Expires:       c.clock().Add(c.lifetime),
	}
	if err := c.transactions.Save(ctx, tx); err != nil {
		return "", err
	}

	return c.oauth.AuthCodeURL(tx.State, protocol.Nonce(tx.Nonce),
		oauth2.S256ChallengeOption(tx.Verifier)), nil
}

// Complete consumes intent before exchanging the code. Any failed exchange
// requires a fresh Begin; uncertain provider effects are never retried here.
func (c *Client) Complete(ctx context.Context, state, browserBinding,
	code string,
) (Identity, error) {
	if len(state) != 43 || len(browserBinding) < 32 ||
		len(browserBinding) > 256 ||
		len(code) == 0 ||
		len(code) > 4096 {
		return Identity{}, ErrDenied
	}

	digest := sha256.Sum256([]byte(browserBinding))
	now := c.clock()

	tx, err := c.transactions.Consume(ctx, state, digest, now)
	if err != nil {
		return Identity{}, ErrDenied
	}

	if tx.State != state || subtle.ConstantTimeCompare(
		tx.BrowserDigest[:], digest[:]) != 1 || !now.Before(tx.Expires) ||
		tx.Expires.After(now.Add(10*time.Minute)) || len(tx.Nonce) != 43 ||
		len(tx.Verifier) < 43 || len(tx.Verifier) > 128 {
		return Identity{}, ErrDenied
	}

	ctx = protocol.ClientContext(ctx, c.http)

	token, err := c.oauth.Exchange(
		ctx,
		code,
		oauth2.VerifierOption(tx.Verifier),
	)
	if err != nil {
		return Identity{}, ErrDenied
	}

	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) == 0 || len(raw) > 65536 {
		return Identity{}, ErrDenied
	}

	verified, err := c.verifier.Verify(ctx, raw)
	if err != nil || verified.Subject == "" || len(verified.Subject) > 255 ||
		subtle.ConstantTimeCompare(
			[]byte(verified.Nonce),
			[]byte(tx.Nonce),
		) != 1 {
		return Identity{}, ErrDenied
	}

	var claims struct {
		AuthorizedParty string `json:"azp"`
	}
	if verified.Claims(&claims) != nil ||
		(len(verified.Audience) > 1 && claims.AuthorizedParty == "") ||
		(claims.AuthorizedParty != "" && claims.AuthorizedParty != c.oauth.ClientID) {
		return Identity{}, ErrDenied
	}

	if verified.AccessTokenHash != "" && verified.VerifyAccessToken(
		token.AccessToken) != nil {
		return Identity{}, ErrDenied
	}

	return Identity{issuer: c.issuer, subject: verified.Subject}, nil
}
