// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package route

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// nodeIDFromPub mirrors swarm's encoding — hex(pubkey).
func nodeIDFromPubBytes(pub ed25519.PublicKey) NodeID {
	id, _ := nodeIDFromPubKey(pub)
	return id
}

func newTestRouter(t *testing.T) *routerImpl {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	r, err := NewRouter(Config{
		NodeID:  nodeIDFromPubBytes(pub),
		PrivKey: priv,
	})
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	return r.(*routerImpl)
}

func makeNode(t *testing.T) (NodeID, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return nodeIDFromPubBytes(pub), priv
}

func TestRouter_AdvertiseAndBestPath(t *testing.T) {
	r := newTestRouter(t)
	target, _ := makeNode(t)
	hop, _ := makeNode(t)

	if err := r.Advertise(target, []NodeID{hop}, "tenant-1", "transit:full"); err != nil {
		t.Fatalf("advertise: %v", err)
	}
	p := r.BestPath(target)
	if p == nil {
		t.Fatal("expected best path, got nil")
	}
	if p.Target != target {
		t.Errorf("target=%q, want %q", p.Target, target)
	}
	if p.NextHop != hop {
		t.Errorf("next hop=%q, want %q (first hop)", p.NextHop, hop)
	}
	if len(p.Hops) != 2 || p.Hops[0] != hop || p.Hops[1] != target {
		t.Errorf("hops=%v, want [%s %s]", p.Hops, hop, target)
	}
}

func TestRouter_DirectPath(t *testing.T) {
	r := newTestRouter(t)
	target, _ := makeNode(t)

	if err := r.Advertise(target, nil, ""); err != nil {
		t.Fatalf("advertise: %v", err)
	}
	p := r.BestPath(target)
	if p == nil {
		t.Fatal("expected best path, got nil")
	}
	if p.NextHop != target {
		t.Errorf("direct path next hop should equal target, got %q", p.NextHop)
	}
}

func TestRouter_Withdraw(t *testing.T) {
	r := newTestRouter(t)
	target, _ := makeNode(t)

	if err := r.Advertise(target, nil, ""); err != nil {
		t.Fatalf("advertise: %v", err)
	}
	if r.BestPath(target) == nil {
		t.Fatal("expected best path before withdraw")
	}
	if err := r.Withdraw(target, ""); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if r.BestPath(target) != nil {
		t.Error("expected nil best path after withdraw")
	}
}

func TestRouter_RejectLoop(t *testing.T) {
	r := newTestRouter(t)
	target, _ := makeNode(t)

	// Loop: local node appears in hops.
	err := r.Advertise(target, []NodeID{r.localID}, "")
	if !errors.Is(err, ErrPathLoop) {
		t.Errorf("expected ErrPathLoop, got %v", err)
	}

	// Loop: duplicate hops.
	hop, _ := makeNode(t)
	err = r.Advertise(target, []NodeID{hop, hop}, "")
	if !errors.Is(err, ErrPathLoop) {
		t.Errorf("expected ErrPathLoop for duplicate hops, got %v", err)
	}

	// Loop: target equals local.
	err = r.Advertise(r.localID, nil, "")
	if !errors.Is(err, ErrPathLoop) {
		t.Errorf("expected ErrPathLoop for self-target, got %v", err)
	}
}

func TestRouter_RejectTooLong(t *testing.T) {
	r := newTestRouter(t)
	r.cfg.MaxHops = 3
	target, _ := makeNode(t)

	hops := make([]NodeID, 5)
	for i := range hops {
		hops[i], _ = makeNode(t)
	}
	err := r.Advertise(target, hops, "")
	if !errors.Is(err, ErrPathTooLong) {
		t.Errorf("expected ErrPathTooLong, got %v", err)
	}
}

func TestRouter_PreferFewerHops(t *testing.T) {
	r := newTestRouter(t)
	target, _ := makeNode(t)

	// First advertisement: 2-hop path.
	hopA, _ := makeNode(t)
	hopB, _ := makeNode(t)
	if err := r.Advertise(target, []NodeID{hopA, hopB}, ""); err != nil {
		t.Fatalf("advertise A: %v", err)
	}

	// Ingest an advertisement from a different origin with a direct path.
	peerNode, peerPriv := makeNode(t)
	ad := &PathAdvertisement{
		Origin:   peerNode,
		Target:   target,
		Hops:     nil,
		Epoch:    1,
		IssuedAt: time.Now(),
	}
	ad.PubKey = peerPriv.Public().(ed25519.PublicKey)
	signable := signableAdvertisement(ad)
	ad.NodeIDSignature = ed25519.Sign(peerPriv, signable)
	if err := r.IngestAdvertisement(ad); err != nil {
		t.Fatalf("ingest direct ad: %v", err)
	}

	best := r.BestPath(target)
	if best == nil {
		t.Fatal("expected best path")
	}
	if best.NextHop != target {
		t.Errorf("expected direct path (fewer hops) to win, got next hop %q", best.NextHop)
	}
}

func TestRouter_PreferLowerRTT(t *testing.T) {
	r := newTestRouter(t)
	target, _ := makeNode(t)

	// Build two ads with identical hop count, different RTT.
	fastNode, fastPriv := makeNode(t)
	slowNode, slowPriv := makeNode(t)

	fast := &PathAdvertisement{
		Origin:      fastNode,
		Target:      target,
		Hops:        nil,
		RTTSampleMs: 5,
		Epoch:       1,
		IssuedAt:    time.Now(),
	}
	fast.PubKey = fastPriv.Public().(ed25519.PublicKey)
	fast.NodeIDSignature = ed25519.Sign(fastPriv, signableAdvertisement(fast))

	slow := &PathAdvertisement{
		Origin:      slowNode,
		Target:      target,
		Hops:        nil,
		RTTSampleMs: 50,
		Epoch:       1,
		IssuedAt:    time.Now(),
	}
	slow.PubKey = slowPriv.Public().(ed25519.PublicKey)
	slow.NodeIDSignature = ed25519.Sign(slowPriv, signableAdvertisement(slow))

	if err := r.IngestAdvertisement(slow); err != nil {
		t.Fatalf("slow: %v", err)
	}
	if err := r.IngestAdvertisement(fast); err != nil {
		t.Fatalf("fast: %v", err)
	}

	best := r.BestPath(target)
	if best == nil {
		t.Fatal("expected best path")
	}
	if best.RTTSampleMs != 5 {
		t.Errorf("expected RTT=5 path, got %d", best.RTTSampleMs)
	}
}

func TestRouter_VerifyBadSignature(t *testing.T) {
	r := newTestRouter(t)
	target, _ := makeNode(t)
	origin, _ := makeNode(t)

	ad := &PathAdvertisement{
		Origin:   origin,
		Target:   target,
		Epoch:    1,
		IssuedAt: time.Now(),
	}
	// Sign with a key that doesn't match the origin NodeID.
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	ad.PubKey = attackerPriv.Public().(ed25519.PublicKey)
	ad.NodeIDSignature = ed25519.Sign(attackerPriv, signableAdvertisement(ad))

	err := r.IngestAdvertisement(ad)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid, got %v", err)
	}
}

func TestRouter_DampingSuppression(t *testing.T) {
	r := newTestRouter(t)
	r.cfg.DampSuppress = 2000
	r.cfg.DampReuse = 750
	r.cfg.DampMaxPenalty = 16000

	target, _ := makeNode(t)
	originNode, originPriv := makeNode(t)

	// Flap repeatedly to accumulate penalty.
	for i := uint64(1); i <= 4; i++ {
		ad := &PathAdvertisement{
			Origin:   originNode,
			Target:   target,
			Epoch:    i,
			IssuedAt: time.Now(),
		}
		ad.PubKey = originPriv.Public().(ed25519.PublicKey)
		ad.NodeIDSignature = ed25519.Sign(originPriv, signableAdvertisement(ad))
		_ = r.IngestAdvertisement(ad)
	}

	key := pathKey{Origin: originNode, Target: target}
	r.mu.RLock()
	state := r.damp[key]
	r.mu.RUnlock()
	if state == nil {
		t.Fatal("expected damping state")
	}
	if state.penalty < r.cfg.DampSuppress {
		t.Errorf("penalty should accumulate past suppress threshold, got %d", state.penalty)
	}
	if !state.suppressed {
		t.Error("expected path to be suppressed after repeated flaps")
	}
	if r.BestPath(target) != nil {
		t.Error("suppressed path should not appear in BestPath")
	}
}

func TestRouter_NetworkScope(t *testing.T) {
	r := newTestRouter(t)
	target, _ := makeNode(t)
	originA, privA := makeNode(t)
	originB, privB := makeNode(t)

	// Advertisement on tenant-1.
	adA := &PathAdvertisement{Origin: originA, Target: target, Epoch: 1, IssuedAt: time.Now(), Network: "tenant-1"}
	adA.PubKey = privA.Public().(ed25519.PublicKey)
	adA.NodeIDSignature = ed25519.Sign(privA, signableAdvertisement(adA))
	_ = r.IngestAdvertisement(adA)

	// Advertisement on tenant-2.
	adB := &PathAdvertisement{Origin: originB, Target: target, Epoch: 1, IssuedAt: time.Now(), Network: "tenant-2"}
	adB.PubKey = privB.Public().(ed25519.PublicKey)
	adB.NodeIDSignature = ed25519.Sign(privB, signableAdvertisement(adB))
	_ = r.IngestAdvertisement(adB)

	// Scoped lookup: only tenant-1 path returned.
	p1 := r.BestPathInNetwork(target, "tenant-1")
	if p1 == nil || p1.Origin != originA {
		t.Errorf("BestPathInNetwork tenant-1 = %+v, want origin %q", p1, originA)
	}
	p2 := r.BestPathInNetwork(target, "tenant-2")
	if p2 == nil || p2.Origin != originB {
		t.Errorf("BestPathInNetwork tenant-2 = %+v, want origin %q", p2, originB)
	}
}

func TestRouter_TransitMode(t *testing.T) {
	r := newTestRouter(t)
	if err := r.SetTransitMode(TransitFull); err != nil {
		t.Fatalf("set transit: %v", err)
	}
	// Round-trips through atomic; just exercise the setter.
	_ = r.SetTransitMode(TransitOptIn)
	_ = r.SetTransitMode(TransitNone)
}

func TestRouter_StaleEpoch(t *testing.T) {
	r := newTestRouter(t)
	target, _ := makeNode(t)
	origin, priv := makeNode(t)

	for _, ep := range []uint64{5, 3} {
		ad := &PathAdvertisement{Origin: origin, Target: target, Epoch: ep, IssuedAt: time.Now()}
		ad.PubKey = priv.Public().(ed25519.PublicKey)
		ad.NodeIDSignature = ed25519.Sign(priv, signableAdvertisement(ad))
		err := r.IngestAdvertisement(ad)
		if ep == 3 && !errors.Is(err, ErrStaleAdvertisement) {
			t.Errorf("expected ErrStaleAdvertisement for epoch 3 after 5, got %v", err)
		}
	}
}
