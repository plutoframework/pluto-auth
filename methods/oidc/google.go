package oidc

import "context"

const GoogleIssuer = "https://accounts.google.com"

// NewGoogle pins Google's issuer. Client credentials, exact registered callback,
// transaction persistence and the host's network policy remain explicit.
func NewGoogle(ctx context.Context, config Config) (*Client, error) {
	if config.Issuer != "" && config.Issuer != GoogleIssuer {
		return nil, ErrConfig
	}

	config.Issuer = GoogleIssuer

	return New(ctx, config)
}
