// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package route

import (
	"errors"
	"testing"
	"time"
)

// The damping state of a key that holds no path, carries no penalty and has
// been quiet for dampRetention is evicted at the next reconvergence; a key
// that still holds a path, or was heard from inside the retention, keeps its
// state.
func TestRouter_QuietDampingStateWithNoPathIsEvicted(t *testing.T) {
	r := newTestRouter(t)
	target, _ := makeNode(t)
	gone, gonePriv := makeNode(t)
	kept, keptPriv := makeNode(t)
	recent, recentPriv := makeNode(t)
	for _, n := range []struct {
		id   NodeID
		priv []byte
	}{{gone, gonePriv}, {kept, keptPriv}, {recent, recentPriv}} {
		if err := r.IngestAdvertisement(signedAd(n.priv, n.id, target, nil, 1)); err != nil {
			t.Fatalf("advertise: %v", err)
		}
	}
	for _, n := range []struct {
		id   NodeID
		priv []byte
	}{{gone, gonePriv}, {recent, recentPriv}} {
		if err := r.IngestWithdrawal(signedWithdrawal(n.priv, n.id, target, 2)); err != nil {
			t.Fatalf("withdraw: %v", err)
		}
	}
	long := time.Now().Add(-2 * r.dampRetention())
	r.mu.Lock()
	r.damp[pathKey{Origin: gone, Target: target}].lastSeen = long
	r.damp[pathKey{Origin: kept, Target: target}].lastSeen = long
	r.mu.Unlock()

	r.reconvergeOnce()

	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.damp[pathKey{Origin: gone, Target: target}]; ok {
		t.Error("the quiet state of a withdrawn key was kept")
	}
	if _, ok := r.damp[pathKey{Origin: kept, Target: target}]; !ok {
		t.Error("the state of a key that still holds a path was evicted")
	}
	if _, ok := r.damp[pathKey{Origin: recent, Target: target}]; !ok {
		t.Error("the state of a key heard from inside the retention was evicted")
	}
}

// Once a key's state is evicted, no lastEpoch is held to refuse a replay of it,
// so an advertisement or withdrawal older than dampRetention is refused by its
// age.
func TestRouter_AMessageOlderThanTheRetentionIsStale(t *testing.T) {
	r := newTestRouter(t)
	target, _ := makeNode(t)
	origin, priv := makeNode(t)
	old := signedAd(priv, origin, target, nil, 1)
	old.IssuedAt = time.Now().Add(-r.dampRetention() - time.Minute)
	resignAd(priv, old)
	if err := r.IngestAdvertisement(old); !errors.Is(err, ErrStaleAdvertisement) {
		t.Fatalf("an advertisement past the retention: %v, want ErrStaleAdvertisement", err)
	}
	w := signedWithdrawal(priv, origin, target, 2)
	w.IssuedAt = old.IssuedAt
	resignWithdrawal(priv, w)
	if err := r.IngestWithdrawal(w); !errors.Is(err, ErrStaleAdvertisement) {
		t.Fatalf("a withdrawal past the retention: %v, want ErrStaleAdvertisement", err)
	}
	if err := r.IngestAdvertisement(signedAd(priv, origin, target, nil, 3)); err != nil {
		t.Fatalf("a fresh advertisement: %v", err)
	}
}
