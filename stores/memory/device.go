package memory

import (
	"context"
	"slices"
	"sync"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/device"
)

// DeviceStore is an in-process device.Store for tests and single-process use.
type DeviceStore struct {
	mutex          sync.Mutex
	authorizations map[auth.Digest]*device.Authorization // by device digest
	byUser         map[auth.Digest]auth.Digest
	grants         map[string]*device.Grant
	access         map[auth.Digest]deviceAccess
	refresh        map[auth.Digest]*deviceRefresh
}

type deviceAccess struct {
	id      string
	grant   string
	expires time.Time
}

type deviceRefresh struct {
	grant   string
	expires time.Time
	used    bool
}

func NewDeviceStore() *DeviceStore {
	return &DeviceStore{
		authorizations: map[auth.Digest]*device.Authorization{},
		byUser:         map[auth.Digest]auth.Digest{},
		grants:         map[string]*device.Grant{},
		access:         map[auth.Digest]deviceAccess{},
		refresh:        map[auth.Digest]*deviceRefresh{},
	}
}

func (s *DeviceStore) CreateAuthorization(
	_ context.Context,
	authorization device.Authorization,
) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, stale := range s.authorizations {
		if !authorization.CreatedAt.Before(stale.ExpiresAt) {
			s.dropAuthorization(stale)
		}
	}

	if _, taken := s.authorizations[authorization.Device]; taken {
		return device.ErrConflict
	}

	if existing, taken := s.byUser[authorization.User]; taken {
		if current, ok := s.authorizations[existing]; ok &&
			authorization.CreatedAt.Before(current.ExpiresAt) {
			return device.ErrConflict
		}
	}

	copied := authorization
	copied.Scopes = slices.Clone(authorization.Scopes)
	s.authorizations[authorization.Device] = &copied
	s.byUser[authorization.User] = authorization.Device

	return nil
}

func (s *DeviceStore) byUserLocked(
	user auth.Digest,
	now time.Time,
) (*device.Authorization, error) {
	key, ok := s.byUser[user]
	if !ok {
		return nil, device.ErrNotFound
	}

	authorization, ok := s.authorizations[key]
	if !ok || !now.Before(authorization.ExpiresAt) {
		return nil, device.ErrNotFound
	}

	return authorization, nil
}

func (s *DeviceStore) FindAuthorization(
	_ context.Context,
	user auth.Digest,
	now time.Time,
) (device.Authorization, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	authorization, err := s.byUserLocked(user, now)
	if err != nil {
		return device.Authorization{}, err
	}

	copied := *authorization
	copied.Scopes = slices.Clone(authorization.Scopes)

	return copied, nil
}

func (s *DeviceStore) Decide(
	_ context.Context,
	user auth.Digest,
	now time.Time,
	decision device.Decision,
) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	authorization, err := s.byUserLocked(user, now)
	if err != nil || authorization.State != device.StatePending {
		return device.ErrNotFound
	}

	if !decision.Approve {
		authorization.State = device.StateDenied

		return nil
	}

	for _, scope := range decision.Scopes {
		if !slices.Contains(authorization.Scopes, scope) {
			return device.ErrScope
		}
	}

	authorization.State = device.StateApproved
	authorization.Subject = decision.Subject
	authorization.Tenant = decision.Tenant
	authorization.Approved = slices.Clone(decision.Scopes)

	return nil
}

func (s *DeviceStore) Poll(
	_ context.Context,
	code auth.Digest,
	now time.Time,
	redemption device.Redemption,
) (device.PollResult, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	authorization, ok := s.authorizations[code]
	if !ok || authorization.ClientID != redemption.ClientID {
		return device.PollResult{}, device.ErrNotFound
	}

	if !now.Before(authorization.ExpiresAt) {
		s.dropAuthorization(authorization)

		return device.PollResult{}, device.ErrExpired
	}

	if !authorization.LastPolled.IsZero() &&
		now.Before(authorization.LastPolled.Add(authorization.Interval)) {
		authorization.Interval += redemption.Step
		authorization.LastPolled = now

		return device.PollResult{
			State:    device.PollSlowDown,
			Interval: authorization.Interval,
		}, nil
	}

	authorization.LastPolled = now

	switch authorization.State {
	case device.StateDenied:
		s.dropAuthorization(authorization)

		return device.PollResult{State: device.PollDenied}, nil
	case device.StateApproved:
		grant := s.issue(authorization, now, redemption)
		s.dropAuthorization(authorization)

		return device.PollResult{State: device.PollIssued, Grant: grant}, nil
	}

	return device.PollResult{
		State:    device.PollPending,
		Interval: authorization.Interval,
	}, nil
}

func (s *DeviceStore) dropAuthorization(a *device.Authorization) {
	delete(s.authorizations, a.Device)

	if s.byUser[a.User] == a.Device {
		delete(s.byUser, a.User)
	}
}

func (s *DeviceStore) issue(
	authorization *device.Authorization,
	now time.Time,
	redemption device.Redemption,
) device.Grant {
	grant := &device.Grant{
		ID:        redemption.GrantID,
		Subject:   authorization.Subject,
		Tenant:    authorization.Tenant,
		ClientID:  authorization.ClientID,
		ActorType: redemption.ActorType,
		Scopes:    slices.Clone(authorization.Approved),
		CreatedAt: now,
		ExpiresAt: now.Add(redemption.MaxLifetime),
	}
	s.grants[grant.ID] = grant
	s.insert(grant, redemption.AccessID, redemption.Access,
		redemption.AccessExpires, redemption.Refresh,
		redemption.RefreshExpires)

	return cloneGrant(grant)
}

func (s *DeviceStore) insert(
	grant *device.Grant,
	accessID string,
	access auth.Digest,
	accessExpires time.Time,
	refresh auth.Digest,
	refreshExpires time.Time,
) {
	if accessExpires.After(grant.ExpiresAt) {
		accessExpires = grant.ExpiresAt
	}

	if refreshExpires.After(grant.ExpiresAt) {
		refreshExpires = grant.ExpiresAt
	}

	s.access[access] = deviceAccess{
		id: accessID, grant: grant.ID, expires: accessExpires,
	}
	s.refresh[refresh] = &deviceRefresh{
		grant:   grant.ID,
		expires: refreshExpires,
	}
}

func (s *DeviceStore) revokeLocked(id string, now time.Time) {
	grant, ok := s.grants[id]
	if !ok || !grant.RevokedAt.IsZero() {
		return
	}

	grant.RevokedAt = now

	for digest, token := range s.access {
		if token.grant == id {
			delete(s.access, digest)
		}
	}
}

func (s *DeviceStore) Rotate(
	_ context.Context,
	presented auth.Digest,
	now time.Time,
	rotation device.Rotation,
) (device.Grant, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, ok := s.refresh[presented]
	if !ok {
		return device.Grant{}, device.ErrNotFound
	}

	grant := s.grants[token.grant]
	if grant == nil || grant.ClientID != rotation.ClientID {
		return device.Grant{}, device.ErrNotFound
	}

	if token.used {
		s.revokeLocked(grant.ID, now)

		return device.Grant{}, device.ErrReuse
	}

	if !grant.Active(now) || !now.Before(token.expires) {
		return device.Grant{}, device.ErrNotFound
	}

	for _, scope := range rotation.Narrow {
		if !slices.Contains(grant.Scopes, scope) {
			return device.Grant{}, device.ErrScope
		}
	}

	if len(rotation.Narrow) > 0 {
		grant.Scopes = slices.Clone(rotation.Narrow)
	}

	token.used = true

	for digest, access := range s.access {
		if access.grant == grant.ID {
			delete(s.access, digest)
		}
	}

	s.insert(grant, rotation.AccessID, rotation.Access, rotation.AccessExpires,
		rotation.Refresh, rotation.RefreshExpires)

	return cloneGrant(grant), nil
}

func (s *DeviceStore) Access(
	_ context.Context,
	digest auth.Digest,
	now time.Time,
) (device.Grant, device.Token, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, ok := s.access[digest]
	if !ok || !now.Before(token.expires) {
		return device.Grant{}, device.Token{}, device.ErrNotFound
	}

	grant := s.grants[token.grant]
	if grant == nil || !grant.Active(now) {
		return device.Grant{}, device.Token{}, device.ErrNotFound
	}

	return cloneGrant(grant),
		device.Token{ID: token.id, ExpiresAt: token.expires}, nil
}

func (s *DeviceStore) RevokeToken(
	_ context.Context,
	digest auth.Digest,
) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if token, ok := s.access[digest]; ok {
		s.revokeLocked(token.grant, time.Now().UTC())
	}

	if token, ok := s.refresh[digest]; ok {
		s.revokeLocked(token.grant, time.Now().UTC())
	}

	return nil
}

func (s *DeviceStore) RevokeGrant(
	_ context.Context,
	subject, id string,
) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	grant, ok := s.grants[id]
	if !ok || grant.Subject != subject || !grant.RevokedAt.IsZero() {
		return device.ErrNotFound
	}

	s.revokeLocked(id, time.Now().UTC())

	return nil
}

func (s *DeviceStore) RevokeSubject(_ context.Context, subject string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for id, grant := range s.grants {
		if grant.Subject == subject {
			s.revokeLocked(id, time.Now().UTC())
		}
	}

	return nil
}

func (s *DeviceStore) ListGrants(
	_ context.Context,
	subject string,
	now time.Time,
) ([]device.Grant, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var out []device.Grant

	for _, grant := range s.grants {
		if grant.Subject == subject && grant.Active(now) {
			out = append(out, cloneGrant(grant))
		}
	}

	slices.SortFunc(out, func(a, b device.Grant) int {
		return a.CreatedAt.Compare(b.CreatedAt)
	})

	return out, nil
}

func (s *DeviceStore) Prune(_ context.Context, now time.Time) (int64, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var removed int64

	for _, authorization := range s.authorizations {
		if !now.Before(authorization.ExpiresAt) {
			s.dropAuthorization(authorization)

			removed++
		}
	}

	for id, grant := range s.grants {
		if !now.Before(grant.ExpiresAt) {
			s.revokeLocked(id, now)

			for digest, token := range s.refresh {
				if token.grant == id {
					delete(s.refresh, digest)
				}
			}

			delete(s.grants, id)

			removed++
		}
	}

	return removed, nil
}

func cloneGrant(grant *device.Grant) device.Grant {
	copied := *grant
	copied.Scopes = slices.Clone(grant.Scopes)

	return copied
}

var _ device.Store = (*DeviceStore)(nil)
