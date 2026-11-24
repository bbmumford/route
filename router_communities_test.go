// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package route

import (
	"testing"
)

// An origin's periodic re-advertisement carries the communities its first
// advertisement did, so a receiver's view of the path keeps them.
func TestRouter_ReemitKeepsTheAdvertisedCommunities(t *testing.T) {
	_, priv := makeNode(t)
	origin, pub := routerWithKey(t, priv)
	target, _ := makeNode(t)
	if err := origin.Advertise(target, nil, "", "relay:tier2", "transit:full"); err != nil {
		t.Fatalf("advertise: %v", err)
	}
	origin.reconvergeOnce()
	if len(pub.ads) != 2 {
		t.Fatalf("published %d advertisements, want the first and its re-emit", len(pub.ads))
	}
	got := pub.ads[1].Communities
	if len(got) != 2 || got[0] != "relay:tier2" || got[1] != "transit:full" {
		t.Fatalf("the re-emit carries communities %q, want [relay:tier2 transit:full]", got)
	}

	receiver := newTestRouter(t)
	for _, ad := range pub.ads {
		if err := receiver.IngestAdvertisement(ad); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}
	p := receiver.BestPath(target)
	if p == nil || len(p.Communities) != 2 || p.Communities[0] != "relay:tier2" {
		t.Fatalf("the receiver's path %+v lost the communities", p)
	}
}
