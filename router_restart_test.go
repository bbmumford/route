// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package route

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// capturePublisher records what a router publishes, standing in for the
// consumer's fabric topic.
type capturePublisher struct {
	ads []*PathAdvertisement
	wds []*PathWithdrawal
}

func (c *capturePublisher) PublishAdvertisement(ad *PathAdvertisement) error {
	c.ads = append(c.ads, ad)
	return nil
}

func (c *capturePublisher) PublishWithdrawal(w *PathWithdrawal) error {
	c.wds = append(c.wds, w)
	return nil
}

func routerWithKey(t *testing.T, priv ed25519.PrivateKey) (*routerImpl, *capturePublisher) {
	t.Helper()
	r, err := NewRouter(Config{NodeID: nodeIDFromPubBytes(priv.Public().(ed25519.PublicKey)), PrivKey: priv})
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	pub := &capturePublisher{}
	r.(*routerImpl).SetPublisher(pub)
	return r.(*routerImpl), pub
}

// An origin that restarts (a new Router with the same key) must have its
// advertisements and withdrawals accepted by a receiver that saw the epochs of
// its previous incarnation.
func TestRouter_RestartedOriginIsNotReadAsStale(t *testing.T) {
	_, priv := makeNode(t)
	receiver := newTestRouter(t)
	target, _ := makeNode(t)
	other, _ := makeNode(t)

	before, pub1 := routerWithKey(t, priv)
	for _, tgt := range []NodeID{other, other, target} {
		if err := before.Advertise(tgt, nil, ""); err != nil {
			t.Fatalf("advertise: %v", err)
		}
	}
	for _, ad := range pub1.ads {
		if err := receiver.IngestAdvertisement(ad); err != nil {
			t.Fatalf("receiver ingest before the restart: %v", err)
		}
	}

	// A restart takes longer than the wall clock's resolution.
	time.Sleep(2 * time.Millisecond)
	after, pub2 := routerWithKey(t, priv)
	if err := after.Advertise(target, nil, ""); err != nil {
		t.Fatalf("advertise after restart: %v", err)
	}
	if err := receiver.IngestAdvertisement(pub2.ads[0]); err != nil {
		t.Fatalf("the restarted origin's advertisement (epoch %d) was refused: %v", pub2.ads[0].Epoch, err)
	}

	if err := after.Withdraw(target, ""); err != nil {
		t.Fatalf("withdraw after restart: %v", err)
	}
	if err := receiver.IngestWithdrawal(pub2.wds[0]); err != nil {
		t.Fatalf("the restarted origin's withdrawal (epoch %d) was refused: %v", pub2.wds[0].Epoch, err)
	}
	if p := receiver.BestPath(target); p != nil {
		t.Fatalf("the withdrawn path is still selected: %+v", p)
	}
}
