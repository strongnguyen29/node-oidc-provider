package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/strongnguyen29/go-oidc-provider/internal/models"
	"github.com/strongnguyen29/go-oidc-provider/internal/store"
)

// newTestAdapter starts an embedded miniredis server and returns an adapter
// pointing at it, the miniredis instance itself (for clock manipulation), and
// a cleanup func.
func newTestAdapter(t *testing.T) (*store.RedisClusterAdapter, *miniredis.Miniredis, func()) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}

	adapter, err := store.NewRedisClusterAdapter(store.RedisClusterOptions{
		Addrs: []string{mr.Addr()},
	})
	if err != nil {
		mr.Close()
		t.Fatalf("NewRedisClusterAdapter: %v", err)
	}

	return adapter, mr, func() {
		adapter.Close()
		mr.Close()
	}
}

// ---------------------------------------------------------------------------
// Upsert + Find round-trips for every model type
// ---------------------------------------------------------------------------

func TestRedisCluster_UpsertFind_Session(t *testing.T) {
	a, _, cleanup := newTestAdapter(t)
	defer cleanup()

	ctx := context.Background()
	sess := &models.Session{
		ID:        "sess-1",
		AccountID: "user-1",
		LoginTime: 1000,
		Clients: map[string]*models.ClientSession{
			"client-a": {GrantID: "grant-1", Consented: []string{"openid"}},
		},
	}

	if err := a.Upsert(ctx, "session:sess-1", sess, time.Minute); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := a.Find(ctx, "session:sess-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}

	result, ok := got.(*models.Session)
	if !ok {
		t.Fatalf("expected *models.Session, got %T", got)
	}
	if result.ID != sess.ID || result.AccountID != sess.AccountID {
		t.Errorf("unexpected session: %+v", result)
	}
	if len(result.Clients) != 1 || result.Clients["client-a"].GrantID != "grant-1" {
		t.Errorf("client session not preserved: %+v", result.Clients)
	}
}

func TestRedisCluster_UpsertFind_AuthorizationCode(t *testing.T) {
	a, _, cleanup := newTestAdapter(t)
	defer cleanup()

	ctx := context.Background()
	ac := &models.AuthorizationCode{
		Code:      "code-abc",
		ClientID:  "client-1",
		AccountID: "user-1",
		Scopes:    []string{"openid", "profile"},
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
	}

	if err := a.Upsert(ctx, "code:code-abc", ac, time.Minute); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := a.Find(ctx, "code:code-abc")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}

	result, ok := got.(*models.AuthorizationCode)
	if !ok {
		t.Fatalf("expected *models.AuthorizationCode, got %T", got)
	}
	if result.Code != ac.Code || result.ClientID != ac.ClientID {
		t.Errorf("unexpected code: %+v", result)
	}
}

func TestRedisCluster_UpsertFind_RefreshToken(t *testing.T) {
	a, _, cleanup := newTestAdapter(t)
	defer cleanup()

	ctx := context.Background()
	rt := &models.RefreshToken{
		ID:        "rt-1",
		AccountID: "user-1",
		ClientID:  "client-1",
		Scopes:    []string{"openid"},
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	if err := a.Upsert(ctx, "rt:rt-1", rt, time.Hour); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := a.Find(ctx, "rt:rt-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	result, ok := got.(*models.RefreshToken)
	if !ok {
		t.Fatalf("expected *models.RefreshToken, got %T", got)
	}
	if result.ID != rt.ID {
		t.Errorf("ID mismatch: %s", result.ID)
	}
}

func TestRedisCluster_UpsertFind_DeviceCode(t *testing.T) {
	a, _, cleanup := newTestAdapter(t)
	defer cleanup()

	ctx := context.Background()
	dc := &models.DeviceCode{
		DeviceCode: "dev-123",
		UserCode:   "ABCD-EFGH",
		ClientID:   "client-1",
		Scopes:     []string{"openid"},
		ExpiresAt:  time.Now().Add(5 * time.Minute).Unix(),
	}

	if err := a.Upsert(ctx, "device:dev-123", dc, 5*time.Minute); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := a.Find(ctx, "device:dev-123")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	result, ok := got.(*models.DeviceCode)
	if !ok {
		t.Fatalf("expected *models.DeviceCode, got %T", got)
	}
	if result.UserCode != dc.UserCode {
		t.Errorf("UserCode mismatch: %s", result.UserCode)
	}
}

func TestRedisCluster_UpsertFind_Grant(t *testing.T) {
	a, _, cleanup := newTestAdapter(t)
	defer cleanup()

	ctx := context.Background()
	g := &models.Grant{
		ID:        "grant-1",
		AccountID: "user-1",
		ClientID:  "client-1",
		Scopes:    []string{"openid", "profile"},
	}

	if err := a.Upsert(ctx, "grant:grant-1", g, time.Hour); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := a.Find(ctx, "grant:grant-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	result, ok := got.(*models.Grant)
	if !ok {
		t.Fatalf("expected *models.Grant, got %T", got)
	}
	if result.ID != g.ID {
		t.Errorf("ID mismatch: %s", result.ID)
	}
}

func TestRedisCluster_UpsertFind_Interaction(t *testing.T) {
	a, _, cleanup := newTestAdapter(t)
	defer cleanup()

	ctx := context.Background()
	ia := &models.Interaction{
		UID:      "ia-1",
		Prompt:   "login",
		ClientID: "client-1",
		Params:   map[string]string{"scope": "openid"},
	}

	if err := a.Upsert(ctx, "interaction:ia-1", ia, 10*time.Minute); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := a.Find(ctx, "interaction:ia-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	result, ok := got.(*models.Interaction)
	if !ok {
		t.Fatalf("expected *models.Interaction, got %T", got)
	}
	if result.UID != ia.UID || result.Prompt != ia.Prompt {
		t.Errorf("unexpected interaction: %+v", result)
	}
}

func TestRedisCluster_UpsertFind_String(t *testing.T) {
	a, _, cleanup := newTestAdapter(t)
	defer cleanup()

	ctx := context.Background()
	if err := a.Upsert(ctx, "usercode:ABCD-EFGH", "dev-123", 5*time.Minute); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := a.Find(ctx, "usercode:ABCD-EFGH")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	s, ok := got.(string)
	if !ok {
		t.Fatalf("expected string, got %T", got)
	}
	if s != "dev-123" {
		t.Errorf("expected dev-123, got %s", s)
	}
}

// ---------------------------------------------------------------------------
// Find: not found and expired
// ---------------------------------------------------------------------------

func TestRedisCluster_Find_NotFound(t *testing.T) {
	a, _, cleanup := newTestAdapter(t)
	defer cleanup()

	_, err := a.Find(context.Background(), "nonexistent-key")
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
}

func TestRedisCluster_Find_Expired(t *testing.T) {
	a, mr, cleanup := newTestAdapter(t)
	defer cleanup()

	ctx := context.Background()
	sess := &models.Session{ID: "sess-exp"}

	if err := a.Upsert(ctx, "session:sess-exp", sess, 5*time.Second); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Advance miniredis clock past the TTL so the key expires.
	mr.FastForward(10 * time.Second)

	_, err := a.Find(ctx, "session:sess-exp")
	if err == nil {
		t.Fatal("expected error for expired key, got nil")
	}
}

// ---------------------------------------------------------------------------
// Consume
// ---------------------------------------------------------------------------

func TestRedisCluster_Consume_AuthorizationCode(t *testing.T) {
	a, _, cleanup := newTestAdapter(t)
	defer cleanup()

	ctx := context.Background()
	ac := &models.AuthorizationCode{
		Code:     "code-consume",
		ClientID: "client-1",
	}

	if err := a.Upsert(ctx, "code:code-consume", ac, time.Minute); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := a.Consume(ctx, "code:code-consume"); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	// The key must still exist after Consume.
	got, err := a.Find(ctx, "code:code-consume")
	if err != nil {
		t.Fatalf("Find after Consume: %v", err)
	}
	result, ok := got.(*models.AuthorizationCode)
	if !ok {
		t.Fatalf("expected *models.AuthorizationCode, got %T", got)
	}
	if !result.Consumed {
		t.Error("expected Consumed = true after Consume")
	}
}

func TestRedisCluster_Consume_RefreshToken(t *testing.T) {
	a, _, cleanup := newTestAdapter(t)
	defer cleanup()

	ctx := context.Background()
	rt := &models.RefreshToken{ID: "rt-consume", ClientID: "client-1"}

	if err := a.Upsert(ctx, "rt:rt-consume", rt, time.Hour); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := a.Consume(ctx, "rt:rt-consume"); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	got, err := a.Find(ctx, "rt:rt-consume")
	if err != nil {
		t.Fatalf("Find after Consume: %v", err)
	}
	result, ok := got.(*models.RefreshToken)
	if !ok {
		t.Fatalf("expected *models.RefreshToken, got %T", got)
	}
	if !result.Consumed {
		t.Error("expected Consumed = true after Consume")
	}
}

func TestRedisCluster_Consume_NotFound(t *testing.T) {
	a, _, cleanup := newTestAdapter(t)
	defer cleanup()

	err := a.Consume(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error consuming missing key, got nil")
	}
}

// ---------------------------------------------------------------------------
// Destroy
// ---------------------------------------------------------------------------

func TestRedisCluster_Destroy(t *testing.T) {
	a, _, cleanup := newTestAdapter(t)
	defer cleanup()

	ctx := context.Background()
	dc := &models.DeviceCode{DeviceCode: "dev-del"}

	if err := a.Upsert(ctx, "device:dev-del", dc, time.Minute); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := a.Destroy(ctx, "device:dev-del"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	_, err := a.Find(ctx, "device:dev-del")
	if err == nil {
		t.Fatal("expected error after Destroy, got nil")
	}
}

func TestRedisCluster_Destroy_NonExistent(t *testing.T) {
	a, _, cleanup := newTestAdapter(t)
	defer cleanup()

	// Destroy on a missing key should not return an error (matches DEL semantics).
	if err := a.Destroy(context.Background(), "no-such-key"); err != nil {
		t.Fatalf("Destroy of nonexistent key returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Upsert overwrites existing entry
// ---------------------------------------------------------------------------

func TestRedisCluster_Upsert_Overwrite(t *testing.T) {
	a, _, cleanup := newTestAdapter(t)
	defer cleanup()

	ctx := context.Background()
	sess := &models.Session{ID: "sess-ow", AccountID: "old-user"}

	if err := a.Upsert(ctx, "session:sess-ow", sess, time.Minute); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}

	sess2 := &models.Session{ID: "sess-ow", AccountID: "new-user"}
	if err := a.Upsert(ctx, "session:sess-ow", sess2, time.Minute); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}

	got, err := a.Find(ctx, "session:sess-ow")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	result, ok := got.(*models.Session)
	if !ok {
		t.Fatalf("expected *models.Session, got %T", got)
	}
	if result.AccountID != "new-user" {
		t.Errorf("expected new-user, got %s", result.AccountID)
	}
}

// ---------------------------------------------------------------------------
// Adapter interface compliance
// ---------------------------------------------------------------------------

// TestRedisCluster_ImplementsAdapter ensures *RedisClusterAdapter satisfies
// the store.Adapter interface at compile time.
func TestRedisCluster_ImplementsAdapter(t *testing.T) {
	var _ store.Adapter = (*store.RedisClusterAdapter)(nil)
}
