// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package route

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// An advertisement is accepted only with both signatures valid: the node
// signature under PubKey, and the per-path signature under the PathPubKey the
// node signature covers.
func TestRouter_ThePathKeySignatureIsChecked(t *testing.T) {
	r := newTestRouter(t)
	target, _ := makeNode(t)
	origin, priv := makeNode(t)

	nodeOnly := &PathAdvertisement{Origin: origin, Target: target, Epoch: 1, IssuedAt: time.Now()}
	nodeOnly.PubKey = priv.Public().(ed25519.PublicKey)
	nodeOnly.NodeIDSignature = ed25519.Sign(priv, signableAdvertisement(nodeOnly))
	if err := r.IngestAdvertisement(nodeOnly); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("an advertisement with no path-key signature: %v, want ErrSignatureInvalid", err)
	}

	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPath := signedAd(priv, origin, target, nil, 2)
	wrongPath.PathPubKey = otherPub
	wrongPath.NodeIDSignature = ed25519.Sign(priv, signableAdvertisement(wrongPath))
	wrongPath.PathKeySignature = ed25519.Sign(otherPriv, signableAdvertisement(wrongPath))
	if err := r.IngestAdvertisement(wrongPath); err != nil {
		t.Fatalf("a path key the node signed for is the path key: %v", err)
	}

	swapped := signedAd(priv, origin, target, nil, 3)
	swapped.PathPubKey = otherPub
	swapped.PathKeySignature = ed25519.Sign(otherPriv, signableAdvertisement(swapped))
	if err := r.IngestAdvertisement(swapped); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("a path key swapped in after the node signed: %v, want ErrSignatureInvalid", err)
	}

	forged := signedAd(priv, origin, target, nil, 4)
	forged.PathKeySignature = ed25519.Sign(otherPriv, signableAdvertisement(forged))
	if err := r.IngestAdvertisement(forged); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("a path signature by a key other than PathPubKey: %v, want ErrSignatureInvalid", err)
	}

	_, opriv := makeNode(t)
	o, pub := routerWithKey(t, opriv)
	if err := o.Advertise(target, nil, ""); err != nil {
		t.Fatal(err)
	}
	if !verifyAdvertisement(pub.ads[0]) || len(pub.ads[0].PathPubKey) != ed25519.PublicKeySize {
		t.Fatal("a router's own advertisement does not verify with its path key")
	}
}
