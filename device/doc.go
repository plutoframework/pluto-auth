// Package device implements the OAuth 2.0 device authorization grant
// (RFC 8628) for delegated clients such as a CLI or an agent, with scoped,
// short-lived access tokens and rotating refresh tokens (reuse revokes the
// whole token family).
//
// It authenticates nothing by itself: the owner approves in a normal browser
// session whose verified identity is passed to Approve. Issued access tokens
// are ordinary auth.Session values carrying a Delegation, so they flow through
// the same identity verification as browser sessions. Roles, permissions and
// tenant membership remain the application's concern: scopes are names that an
// application maps to permissions and intersects with the owner's own.
package device
