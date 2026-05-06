package store_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/strongnguyen29/go-oidc-provider/internal/models"
	"github.com/strongnguyen29/go-oidc-provider/internal/store"
)

// ---------------------------------------------------------------------------
// Compile-time interface check
// ---------------------------------------------------------------------------

var _ store.Adapter = (*store.MemoryStore)(nil)

// ---------------------------------------------------------------------------
// Upsert + Find
// ---------------------------------------------------------------------------

func TestMemoryStore_UpsertFind(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Stop()

	ctx := context.Background()
	if err := s.Upsert(ctx, "key1", "hello", time.Minute); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := s.Find(ctx, "key1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got != "hello" {
		t.Errorf("expected hello, got %v", got)
	}
}

func TestMemoryStore_Find_NotFound(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Stop()

	_, err := s.Find(context.Background(), "missing-key")
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
}

func TestMemoryStore_Find_Expired(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Stop()

	ctx := context.Background()
	// Store with a TTL that is already past.
	if err := s.Upsert(ctx, "exp-key", "value", -time.Second); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	_, err := s.Find(ctx, "exp-key")
	if err == nil {
		t.Fatal("expected error for expired key, got nil")
	}
}

func TestMemoryStore_Find_Expired_AfterSleep(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Stop()

	ctx := context.Background()
	if err := s.Upsert(ctx, "ttl-key", "value", 10*time.Millisecond); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	_, err := s.Find(ctx, "ttl-key")
	if err == nil {
		t.Fatal("expected error for key past its TTL, got nil")
	}
}

func TestMemoryStore_Upsert_Overwrite(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Stop()

	ctx := context.Background()
	s.Upsert(ctx, "k", "first", time.Minute)
	s.Upsert(ctx, "k", "second", time.Minute)

	got, err := s.Find(ctx, "k")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got != "second" {
		t.Errorf("expected second, got %v", got)
	}
}

func TestMemoryStore_UpsertFind_StructPayload(t *testing.T) {
	type myStruct struct {
		Name string
		Age  int
	}

	s := store.NewMemoryStore()
	defer s.Stop()

	ctx := context.Background()
	orig := myStruct{Name: "Alice", Age: 30}
	s.Upsert(ctx, "struct-key", orig, time.Minute)

	got, err := s.Find(ctx, "struct-key")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got != orig {
		t.Errorf("expected %v, got %v", orig, got)
	}
}

// ---------------------------------------------------------------------------
// Consume
// ---------------------------------------------------------------------------

func TestMemoryStore_Consume_MarksConsumed(t *testing.T) {
	// MemoryStore.Consume only marks the internal consumed flag; it does not
	// expose it through Find (which returns the raw payload). We verify that
	// Consume on an existing key returns no error and the key is still findable.
	s := store.NewMemoryStore()
	defer s.Stop()

	ctx := context.Background()
	s.Upsert(ctx, "consume-key", "payload", time.Minute)

	if err := s.Consume(ctx, "consume-key"); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	// Key should still exist after Consume.
	if _, err := s.Find(ctx, "consume-key"); err != nil {
		t.Errorf("key should still be findable after Consume: %v", err)
	}
}

func TestMemoryStore_Consume_NotFound(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Stop()

	err := s.Consume(context.Background(), "no-such-key")
	if err == nil {
		t.Fatal("expected error for consuming missing key, got nil")
	}
}

// ---------------------------------------------------------------------------
// Destroy
// ---------------------------------------------------------------------------

func TestMemoryStore_Destroy_RemovesKey(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Stop()

	ctx := context.Background()
	s.Upsert(ctx, "del-key", "value", time.Minute)
	if err := s.Destroy(ctx, "del-key"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	_, err := s.Find(ctx, "del-key")
	if err == nil {
		t.Fatal("expected error after Destroy, got nil")
	}
}

func TestMemoryStore_Destroy_Idempotent(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Stop()

	ctx := context.Background()
	// Destroy a key that was never stored — should not error.
	if err := s.Destroy(ctx, "nonexistent"); err != nil {
		t.Fatalf("Destroy of nonexistent key returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Stop / eviction goroutine
// ---------------------------------------------------------------------------

func TestMemoryStore_Stop_DoesNotPanic(t *testing.T) {
	s := store.NewMemoryStore()
	s.Stop() // must not panic or block
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestMemoryStore_Concurrent(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Stop()

	ctx := context.Background()
	done := make(chan struct{})

	for i := 0; i < 10; i++ {
		go func(n int) {
			key := "k"
			for j := 0; j < 100; j++ {
				s.Upsert(ctx, key, n*100+j, time.Minute)
				s.Find(ctx, key)
				s.Consume(ctx, key)
			}
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestFindReturnsIsolatedCopy asserts that mutating the value returned from
// Find does not leak into the underlying entry, so a second Find call sees
// the original data.
func TestFindReturnsIsolatedCopy(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Stop()
	ctx := context.Background()

	original := &models.Session{
		ID:        "s1",
		AccountID: "alice",
		LoginTime: 12345,
		Clients: map[string]*models.ClientSession{
			"client-1": {GrantID: "g1", Consented: []string{"openid"}},
		},
	}
	if err := s.Upsert(ctx, "session:s1", original, time.Minute); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := s.Find(ctx, "session:s1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	sess := got.(*models.Session)
	sess.AccountID = "mallory"
	sess.Clients["client-1"].Consented = append(sess.Clients["client-1"].Consented, "evil")

	got2, err := s.Find(ctx, "session:s1")
	if err != nil {
		t.Fatalf("Find again: %v", err)
	}
	sess2 := got2.(*models.Session)
	if sess2.AccountID != "alice" {
		t.Errorf("expected AccountID=alice after first reader's mutation, got %s", sess2.AccountID)
	}
	if len(sess2.Clients["client-1"].Consented) != 1 {
		t.Errorf("expected Consented unchanged, got %v", sess2.Clients["client-1"].Consented)
	}
}

// TestConcurrentSessionMutation hammers Find/Upsert with many goroutines that
// each mutate the value they retrieve. Run with -race to catch shared-pointer
// bugs in the in-memory adapter.
func TestConcurrentSessionMutation(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Stop()
	ctx := context.Background()

	if err := s.Upsert(ctx, "session:race", &models.Session{
		ID:        "race",
		AccountID: "alice",
		Clients:   map[string]*models.ClientSession{"c": {Consented: []string{"openid"}}},
	}, time.Minute); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				got, err := s.Find(ctx, "session:race")
				if err != nil {
					continue
				}
				if sess, ok := got.(*models.Session); ok {
					sess.LoginTime = int64(n*1000 + j)
					if cs := sess.Clients["c"]; cs != nil {
						cs.Consented = append(cs.Consented, "x")
					}
				}
			}
		}(i)
	}
	wg.Wait()
}
