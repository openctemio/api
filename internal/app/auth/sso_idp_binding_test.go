package auth

import (
	"context"
	"testing"

	identityproviderdom "github.com/openctemio/api/pkg/domain/identityprovider"
	userdom "github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
)

// ssoFakeUserRepo records Create/Update for the SSO findOrCreateUser tests.
// (fakeUserRepo from oauth_takeover_test.go is reused where it suffices, but we
// need to observe Update here, so define a local one.)
type ssoFakeUserRepo struct {
	userdom.Repository
	byEmail *userdom.User
	created *userdom.User
	updated *userdom.User
}

func (r *ssoFakeUserRepo) GetByEmail(_ context.Context, _ string) (*userdom.User, error) {
	return r.byEmail, nil
}
func (r *ssoFakeUserRepo) Update(_ context.Context, u *userdom.User) error { r.updated = u; return nil }
func (r *ssoFakeUserRepo) Create(_ context.Context, u *userdom.User) error { r.created = u; return nil }

func newSSOSvc(existing *userdom.User) (*SSOService, *ssoFakeUserRepo) {
	repo := &ssoFakeUserRepo{byEmail: existing}
	return &SSOService{userRepo: repo, logger: logger.NewNop()}, repo
}

const (
	corpOkta   = "https://corp.okta.com"
	evilOkta   = "https://attacker.okta.com"
	victimMail = "victim@corp.com"
)

// THE HEADLINE FIX: a federated account bound to one OIDC issuer (corp Okta)
// must NOT be adoptable by a DIFFERENT OIDC issuer (attacker's own Okta) that
// asserts the same verified email — even though both collapse to
// AuthProviderOIDC and the provider-match check passes.
func TestSSOFindOrCreate_BlocksCrossIdPSameEnum(t *testing.T) {
	victim, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim") // AuthProviderOIDC
	victim.BindFederatedIdentity(corpOkta, "corp-sub")
	s, repo := newSSOSvc(victim)

	got, err := s.findOrCreateUser(context.Background(),
		&SSOUserInfo{Email: victimMail, Issuer: evilOkta, Subject: "evil-sub"},
		identityproviderdom.ProviderOkta)

	if err == nil {
		t.Fatal("expected cross-IdP takeover (corp account ← attacker Okta) to be BLOCKED")
	}
	if got != nil {
		t.Fatalf("blocked login must not return a user, got %v", got)
	}
	if repo.updated != nil || repo.created != nil {
		t.Fatal("blocked login must not persist any change")
	}
	// The binding must be unchanged (still corp).
	if iss := victim.FederatedIssuer(); iss == nil || *iss != corpOkta {
		t.Fatalf("victim issuer must stay %q, got %v", corpOkta, iss)
	}
}

// Re-login from the SAME issuer is fine.
func TestSSOFindOrCreate_SameIssuerOK(t *testing.T) {
	u, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim")
	u.BindFederatedIdentity(corpOkta, "corp-sub")
	s, _ := newSSOSvc(u)

	got, err := s.findOrCreateUser(context.Background(),
		&SSOUserInfo{Email: victimMail, Issuer: corpOkta, Subject: "corp-sub"},
		identityproviderdom.ProviderOkta)
	if err != nil {
		t.Fatalf("same-issuer re-login should succeed, got %v", err)
	}
	if got == nil {
		t.Fatal("expected the existing user back")
	}
}

// A pre-tracking federated account (no recorded issuer) is bound on first use
// (trust-on-first-use) and adopted; subsequent logins are then enforced.
func TestSSOFindOrCreate_LegacyTrustOnFirstUseBinds(t *testing.T) {
	legacy, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim") // no federated issuer
	if legacy.FederatedIssuer() != nil {
		t.Fatal("precondition: legacy user must start unbound")
	}
	s, repo := newSSOSvc(legacy)

	got, err := s.findOrCreateUser(context.Background(),
		&SSOUserInfo{Email: victimMail, Issuer: corpOkta, Subject: "corp-sub"},
		identityproviderdom.ProviderOkta)
	if err != nil {
		t.Fatalf("legacy first-use login should succeed, got %v", err)
	}
	if got == nil {
		t.Fatal("expected the existing user back")
	}
	if iss := got.FederatedIssuer(); iss == nil || *iss != corpOkta {
		t.Fatalf("expected issuer bound to %q on first use, got %v", corpOkta, iss)
	}
	if repo.updated == nil {
		t.Fatal("the newly-bound identity must be persisted via Update")
	}
}

// When the provider returns no id_token (issuer empty) we cannot bind/verify;
// the login must still work (no regression) — falling back to the existing
// provider-match guard.
func TestSSOFindOrCreate_NoIssuerNoRegression(t *testing.T) {
	u, _ := userdom.NewFromKeycloak("kc-1", victimMail, "Victim")
	u.BindFederatedIdentity(corpOkta, "corp-sub")
	s, _ := newSSOSvc(u)

	got, err := s.findOrCreateUser(context.Background(),
		&SSOUserInfo{Email: victimMail, Issuer: "", Subject: ""},
		identityproviderdom.ProviderOkta)
	if err != nil {
		t.Fatalf("no-id_token login should not regress, got %v", err)
	}
	if got == nil {
		t.Fatal("expected the existing user back")
	}
}

// A brand-new federated user records the IdP issuer at creation. Entra
// (→Microsoft) is used because NewOAuthUser accepts it.
func TestSSOFindOrCreate_NewUserBindsIssuer(t *testing.T) {
	s, repo := newSSOSvc(nil) // no existing user
	const entraIss = "https://login.microsoftonline.com/dir/v2.0"

	got, err := s.findOrCreateUser(context.Background(),
		&SSOUserInfo{Email: "new@corp.com", Name: "New", Issuer: entraIss, Subject: "entra-sub"},
		identityproviderdom.ProviderEntraID)
	if err != nil {
		t.Fatalf("new federated user creation should succeed, got %v", err)
	}
	if got == nil || repo.created == nil {
		t.Fatal("expected a created user")
	}
	if iss := repo.created.FederatedIssuer(); iss == nil || *iss != entraIss {
		t.Fatalf("new user must be bound to %q, got %v", entraIss, iss)
	}
}
