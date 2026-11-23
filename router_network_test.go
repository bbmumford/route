// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package route

import "testing"

// staticNetworks is a NetworkContextProvider answering a fixed membership.
type staticNetworks []NetworkID

func (s staticNetworks) LocalNetworks() []NetworkID { return s }

// BestPath returns a network-scoped path only to a member of that network,
// and a fleet-wide path to every node.
func TestRouter_BestPathSkipsAPathInANetworkTheNodeIsNotIn(t *testing.T) {
	_, priv := makeNode(t)
	origin, pub := routerWithKey(t, priv)
	outsider := newTestRouter(t)
	member := newTestRouter(t)
	member.netCtx = staticNetworks{"net-x"}
	scoped, _ := makeNode(t)
	fleet, _ := makeNode(t)

	if err := origin.Advertise(scoped, nil, "net-x"); err != nil {
		t.Fatalf("advertise in net-x: %v", err)
	}
	if err := origin.Advertise(fleet, nil, ""); err != nil {
		t.Fatalf("advertise fleet-wide: %v", err)
	}
	for _, ad := range pub.ads {
		for _, r := range []*routerImpl{outsider, member} {
			if err := r.IngestAdvertisement(ad); err != nil {
				t.Fatalf("ingest: %v", err)
			}
		}
	}

	if p := outsider.BestPath(scoped); p != nil {
		t.Fatalf("a node in no network was given a net-x path: %+v", p)
	}
	if p := member.BestPath(scoped); p == nil || p.Network != "net-x" {
		t.Fatalf("a member of net-x was not given its net-x path: %+v", p)
	}
	for name, r := range map[string]*routerImpl{"outsider": outsider, "member": member} {
		if p := r.BestPath(fleet); p == nil || p.Network != "" {
			t.Fatalf("%s was not given the fleet-wide path: %+v", name, p)
		}
	}
}
