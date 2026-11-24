// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package route

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// A stable origin re-advertises the same direct edge every reconvergeInterval.
// Each refresh carries a new epoch and the same hops and RTT, so a receiver
// must keep the path usable however many refreshes arrive.
func TestRouter_RefreshOfAnUnchangedRemotePathIsNotDamped(t *testing.T) {
	_, priv := makeNode(t)
	origin, pub := routerWithKey(t, priv)
	receiver := newTestRouter(t)
	target, _ := makeNode(t)

	for i := 0; i < 8; i++ {
		if err := origin.Advertise(target, nil, ""); err != nil {
			t.Fatalf("advertise: %v", err)
		}
	}
	for i, ad := range pub.ads {
		if err := receiver.IngestAdvertisement(ad); err != nil {
			t.Fatalf("refresh %d of an unchanged direct edge: %v", i+1, err)
		}
	}
	if p := receiver.BestPath(target); p == nil {
		t.Fatal("the refreshed path is not selected")
	}
}

func signedAd(priv ed25519.PrivateKey, origin, target NodeID, hops []NodeID, epoch uint64) *PathAdvertisement {
	ad := &PathAdvertisement{Origin: origin, Target: target, Hops: hops, Epoch: epoch, IssuedAt: time.Now()}
	resignAd(priv, ad)
	return ad
}

func signedWithdrawal(priv ed25519.PrivateKey, origin, target NodeID, epoch uint64) *PathWithdrawal {
	w := &PathWithdrawal{Origin: origin, Target: target, Epoch: epoch, IssuedAt: time.Now()}
	resignWithdrawal(priv, w)
	return w
}

// resignAd signs ad again after a test changes a signed field.
func resignAd(priv ed25519.PrivateKey, ad *PathAdvertisement) {
	ad.PubKey = priv.Public().(ed25519.PublicKey)
	ad.NodeIDSignature = ed25519.Sign(priv, signableAdvertisement(ad))
}

// resignWithdrawal signs w again after a test changes a signed field.
func resignWithdrawal(priv ed25519.PrivateKey, w *PathWithdrawal) {
	w.PubKey = priv.Public().(ed25519.PublicKey)
	w.Signature = ed25519.Sign(priv, signableWithdrawal(w))
}

// A path withdrawn and advertised again is a flap: three returns after
// withdrawals push the penalty past DampSuppress and the path is suppressed.
func TestRouter_WithdrawAndReadvertiseIsDamped(t *testing.T) {
	r := newTestRouter(t)
	target, _ := makeNode(t)
	origin, priv := makeNode(t)

	var last error
	epoch := uint64(0)
	for i := 0; i < 4; i++ {
		epoch++
		last = r.IngestAdvertisement(signedAd(priv, origin, target, nil, epoch))
		if i < 3 {
			epoch++
			if err := r.IngestWithdrawal(signedWithdrawal(priv, origin, target, epoch)); err != nil {
				t.Fatalf("withdrawal %d: %v", i+1, err)
			}
		}
	}
	if !errors.Is(last, ErrPathSuppressed) {
		t.Fatalf("fourth advertisement after three withdrawals: %v, want ErrPathSuppressed", last)
	}
	if p := r.BestPath(target); p != nil {
		t.Fatalf("a suppressed path is selected: %+v", p)
	}
}
