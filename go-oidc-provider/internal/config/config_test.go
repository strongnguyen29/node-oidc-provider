package config_test

import (
	"context"
	"testing"
	"time"

	"github.com/strongnguyen29/go-oidc-provider/internal/config"
)

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

func TestDefaults_AppliedToZeroValues(t *testing.T) {
	cfg := &config.Config{} // all zero
	cfg.Defaults()

	if cfg.AccessTokenTTL == 0 {
		t.Error("AccessTokenTTL should have a default")
	}
	if cfg.AuthCodeTTL == 0 {
		t.Error("AuthCodeTTL should have a default")
	}
	if cfg.RefreshTokenTTL == 0 {
		t.Error("RefreshTokenTTL should have a default")
	}
	if cfg.DeviceCodeTTL == 0 {
		t.Error("DeviceCodeTTL should have a default")
	}
	if cfg.DeviceInterval == 0 {
		t.Error("DeviceInterval should have a default")
	}
	if len(cfg.Scopes) == 0 {
		t.Error("Scopes should have a default")
	}
	if len(cfg.GrantTypes) == 0 {
		t.Error("GrantTypes should have a default")
	}
}

func TestDefaults_DoNotOverwriteExisting(t *testing.T) {
	cfg := &config.Config{
		AccessTokenTTL:  5 * time.Minute,
		AuthCodeTTL:     2 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		DeviceCodeTTL:   3 * time.Minute,
		DeviceInterval:  10,
		Scopes:          []string{"openid"},
		GrantTypes:      []string{"authorization_code"},
	}
	cfg.Defaults()

	if cfg.AccessTokenTTL != 5*time.Minute {
		t.Errorf("AccessTokenTTL should not be overwritten: got %v", cfg.AccessTokenTTL)
	}
	if cfg.AuthCodeTTL != 2*time.Minute {
		t.Errorf("AuthCodeTTL should not be overwritten: got %v", cfg.AuthCodeTTL)
	}
	if cfg.RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("RefreshTokenTTL should not be overwritten: got %v", cfg.RefreshTokenTTL)
	}
	if cfg.DeviceCodeTTL != 3*time.Minute {
		t.Errorf("DeviceCodeTTL should not be overwritten: got %v", cfg.DeviceCodeTTL)
	}
	if cfg.DeviceInterval != 10 {
		t.Errorf("DeviceInterval should not be overwritten: got %d", cfg.DeviceInterval)
	}
	if len(cfg.Scopes) != 1 || cfg.Scopes[0] != "openid" {
		t.Errorf("Scopes should not be overwritten: got %v", cfg.Scopes)
	}
	if len(cfg.GrantTypes) != 1 || cfg.GrantTypes[0] != "authorization_code" {
		t.Errorf("GrantTypes should not be overwritten: got %v", cfg.GrantTypes)
	}
}

func TestDefaults_DefaultScopesContainOpenID(t *testing.T) {
	cfg := &config.Config{}
	cfg.Defaults()

	found := false
	for _, s := range cfg.Scopes {
		if s == "openid" {
			found = true
			break
		}
	}
	if !found {
		t.Error("default Scopes should include 'openid'")
	}
}

func TestDefaults_DefaultGrantTypesContainAuthCode(t *testing.T) {
	cfg := &config.Config{}
	cfg.Defaults()

	found := false
	for _, g := range cfg.GrantTypes {
		if g == "authorization_code" {
			found = true
			break
		}
	}
	if !found {
		t.Error("default GrantTypes should include 'authorization_code'")
	}
}

// ---------------------------------------------------------------------------
// FindClient
// ---------------------------------------------------------------------------

func TestFindClient_Found(t *testing.T) {
	cfg := &config.Config{
		Clients: []config.ClientConfig{
			{ID: "alpha", Secret: "s1"},
			{ID: "beta", Secret: "s2"},
		},
	}

	c := cfg.FindClient("beta")
	if c == nil {
		t.Fatal("expected to find client 'beta', got nil")
	}
	if c.ID != "beta" {
		t.Errorf("expected ID=beta, got %s", c.ID)
	}
}

func TestFindClient_NotFound(t *testing.T) {
	cfg := &config.Config{
		Clients: []config.ClientConfig{
			{ID: "alpha"},
		},
	}
	if c := cfg.FindClient("unknown"); c != nil {
		t.Errorf("expected nil for unknown client, got %+v", c)
	}
}

func TestFindClient_EmptyList(t *testing.T) {
	cfg := &config.Config{}
	if c := cfg.FindClient("anything"); c != nil {
		t.Errorf("expected nil for empty client list, got %+v", c)
	}
}

func TestFindClient_FirstMatch(t *testing.T) {
	cfg := &config.Config{
		Clients: []config.ClientConfig{
			{ID: "dup", Secret: "first"},
			{ID: "dup", Secret: "second"},
		},
	}
	c := cfg.FindClient("dup")
	if c == nil {
		t.Fatal("expected a result for duplicate client IDs")
	}
	if c.Secret != "first" {
		t.Errorf("expected first match to be returned, got secret=%s", c.Secret)
	}
}

// ---------------------------------------------------------------------------
// Account — compile-time structure checks
// ---------------------------------------------------------------------------

func TestAccount_Structure(t *testing.T) {
	acc := &config.Account{
		Sub: "user-1",
		Claims: map[string]interface{}{
			"name":  "Test User",
			"email": "test@example.com",
		},
	}
	if acc.Sub != "user-1" {
		t.Errorf("Sub mismatch: %s", acc.Sub)
	}
	if acc.Claims["name"] != "Test User" {
		t.Errorf("Claims mismatch: %v", acc.Claims)
	}
}

// ---------------------------------------------------------------------------
// Config callback fields
// ---------------------------------------------------------------------------

func TestConfig_FindAccountCallback(t *testing.T) {
	cfg := &config.Config{
		FindAccount: func(ctx context.Context, sub string) (*config.Account, error) {
			if sub == "alice" {
				return &config.Account{Sub: "alice"}, nil
			}
			return nil, nil
		},
	}

	acc, err := cfg.FindAccount(context.Background(), "alice")
	if err != nil {
		t.Fatalf("FindAccount: %v", err)
	}
	if acc == nil || acc.Sub != "alice" {
		t.Errorf("expected alice, got %v", acc)
	}

	acc2, err2 := cfg.FindAccount(context.Background(), "unknown")
	if err2 != nil {
		t.Fatalf("unexpected error: %v", err2)
	}
	if acc2 != nil {
		t.Errorf("expected nil for unknown user, got %v", acc2)
	}
}

func TestConfig_AuthenticateAccountCallback(t *testing.T) {
	cfg := &config.Config{
		AuthenticateAccount: func(ctx context.Context, login, password string) (*config.Account, error) {
			if login == "alice" && password == "correct" {
				return &config.Account{Sub: "alice"}, nil
			}
			return nil, nil
		},
	}

	acc, err := cfg.AuthenticateAccount(context.Background(), "alice", "correct")
	if err != nil || acc == nil {
		t.Fatalf("expected successful auth, err=%v acc=%v", err, acc)
	}

	rejected, err2 := cfg.AuthenticateAccount(context.Background(), "alice", "wrong")
	if err2 != nil {
		t.Fatalf("unexpected error: %v", err2)
	}
	if rejected != nil {
		t.Error("expected nil for wrong password")
	}
}
