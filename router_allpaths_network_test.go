// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package route

import "testing"

// AllPaths lists a network-scoped path only to a member of that network, as
// BestPath does, and a fleet-wide path to every node.
func TestRouter_AllPathsSkipsAPathInANetworkTheNodeIsNotIn(t *testing.T) {
	_, priv := makeNode(t)
	origin, pub := routerWithKey(t, priv)
	outsider := newTestRouter(t)
	member := newTestRouter(t)
	member.netCtx = staticNetworks{"net-x"}
	target, _ := makeNode(t)

	if err := origin.Advertise(target, nil, "net-x"); err != nil {
		t.Fatalf("advertise in net-x: %v", err)
	}
	if err := origin.Advertise(target, nil, ""); err != nil {
		t.Fatalf("advertise fleet-wide: %v", err)
	}
	for _, ad := range pub.ads {
		for _, r := range []*routerImpl{outsider, member} {
			if err := r.IngestAdvertisement(ad); err != nil {
				t.Fatalf("ingest: %v", err)
			}
		}
	}

	if got := outsider.AllPaths(target); len(got) != 1 || got[0].Network != "" {
		t.Fatalf("a node in no network was given %d paths (%+v); want only the fleet-wide one", len(got), got)
	}
	if got := member.AllPaths(target); len(got) != 2 {
		t.Fatalf("a member of net-x was given %d paths; want the fleet-wide one and its net-x one", len(got))
	}
}
