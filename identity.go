package auth

import (
	"context"
	"sync"
)

// Identity is an opaque session-verified callback-lifetime identity. Copies
// share expiration state. Its zero value cannot authorize a use. It grants no
// role, permission, tenant membership or resource ownership.
type Identity struct {
	state *identityState
}

type identityState struct {
	manager *Manager
	digest  Digest
	subject string
	session string
	context context.Context
	mutex   sync.Mutex
	closed  *sync.Cond
	active  bool
	uses    int
}

// WithIdentity verifies a bearer session using the existing store contract and
// supplies a restricted identity to run. No public string constructor exists.
// When run returns or panics, admission closes and active uses finish before
// the scope returns. Session issuance remains a trusted credential-verifier
// boundary: callers of Start must already have verified credentials.
func (m *Manager) WithIdentity(
	ctx context.Context,
	token string,
	run func(context.Context, *Identity) error,
) error {
	if m == nil || m.store == nil || m.config.Clock == nil || ctx == nil ||
		run == nil {
		return ErrInvalidConfig
	}

	session, err := m.Authenticate(ctx, token)
	if err != nil {
		return err
	}

	digest, err := TokenDigest(token)
	if err != nil {
		return ErrUnauthenticated
	}

	state := &identityState{
		manager: m,
		digest:  digest,
		subject: session.SubjectID,
		session: session.ID,
		context: ctx,
		active:  true,
	}

	state.closed = sync.NewCond(&state.mutex)
	defer state.close()

	return run(ctx, &Identity{state: state})
}

func (s *identityState) close() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.active = false
	for s.uses > 0 {
		s.closed.Wait()
	}
}

func (s *identityState) finish() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.uses--
	s.closed.Broadcast()
}

// Use revalidates the session, expiry and revocation before invoking run with
// its verified subject. A supplied context cannot erase the original
// cancellation. Only the digest is retained, never the raw bearer token.
// Identity is not a reusable proof: every use consults the configured store
// again. Store freshness and revocation races after validation remain the
// documented session contract.
func (i *Identity) Use(
	ctx context.Context,
	run func(context.Context, string) error,
) error {
	if ctx == nil || run == nil {
		return ErrInvalidConfig
	}

	if i == nil || i.state == nil {
		return ErrUnauthenticated
	}

	state := i.state
	state.mutex.Lock()

	if !state.active {
		state.mutex.Unlock()

		return ErrUnauthenticated
	}

	state.uses++

	state.mutex.Unlock()
	defer state.finish()

	// Keep values from the use context and cancellation from both scopes.
	ctx, cancel := context.WithCancel(ctx)

	stop := context.AfterFunc(state.context, cancel)
	defer cancel()
	defer stop()

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := state.context.Err(); err != nil {
		return err
	}

	session, err := state.manager.authenticateDigest(ctx, state.digest)
	if err != nil {
		return err
	}

	if session.ID != state.session || session.SubjectID != state.subject {
		return ErrUnauthenticated
	}

	state.mutex.Lock()

	active := state.active
	state.mutex.Unlock()

	if !active {
		return ErrUnauthenticated
	}

	if err := state.context.Err(); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return run(ctx, state.subject)
}

// UseIdentity accepts only identities created by this exact trusted manager. A
// different Manager or a caller-provided Session cannot establish provenance.
func (m *Manager) UseIdentity(
	ctx context.Context,
	identity *Identity,
	run func(context.Context, string) error,
) error {
	if m == nil || identity == nil || identity.state == nil ||
		identity.state.manager != m {
		return ErrUnauthenticated
	}

	return identity.Use(ctx, run)
}
