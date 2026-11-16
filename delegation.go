package auth

import "slices"

// Delegation describes a session issued to a delegated client through the
// device authorization grant. Scopes are the declared scope names the owner
// approved; applications map them to permissions and intersect them with the
// owner's live permissions, so a delegation can only narrow access.
type Delegation struct {
	GrantID   string
	ClientID  string
	ActorType string
	Tenant    string
	Scopes    []string
}

func (d *Delegation) clone() *Delegation {
	if d == nil {
		return nil
	}

	copied := *d
	copied.Scopes = slices.Clone(d.Scopes)

	return &copied
}

// HasScope reports whether the delegation carries the exact scope name.
func (d Delegation) HasScope(scope string) bool {
	return slices.Contains(d.Scopes, scope)
}
