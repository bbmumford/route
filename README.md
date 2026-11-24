# route

route chooses paths through a mesh of nodes. Each node advertises the peers it
can reach as signed path advertisements: the target, the hops to it, a
round-trip-time sample, an epoch and optional community tags. Every router
checks the advertisements it receives, damps paths that keep changing, and
keeps a forwarding table from which `BestPath` answers the next hop towards any
target.

route carries no traffic and does no gossip itself. The caller gives the router
an `AdvertisementPublisher` that puts its advertisements and withdrawals on the
caller's own fabric, and hands every advertisement and withdrawal it receives
to `IngestAdvertisement` and `IngestWithdrawal`.

How a router decides:

- **Checks.** An advertisement is refused when its hops loop or include the
  target, when it has more hops than `MaxHops` (default 8), when its public key
  does not hash to the origin's NodeID (a `vl1_` fingerprint of the Ed25519
  key, the form aether uses), or when the origin's signature fails. Each
  advertisement also carries a per-path public key, covered by the origin's
  signature, and a second signature made with that per-path key; it is
  accepted only when that signature verifies, and one with no path signature
  is refused.
- **Epochs.** A router seeds its epoch counter from the clock when it starts,
  so a restarted node's advertisements order after the ones it sent before.
  A receiver refuses an epoch at or below the last one it holds for that
  origin, target and network.
- **Damping.** Flap damping follows RFC 2439: a path whose hops or round-trip
  time change gains penalty, is suppressed above `DampSuppress` (default 2000)
  and comes back below `DampReuse` (default 750), with the penalty halving
  every `DampHalfLife` (default 15 minutes). A refresh of the same path with a
  new epoch is not a flap.
- **Selection.** Among the paths to a target, the fewest hops win, then the
  lowest round-trip time, then the smallest origin NodeID. `BestPath` looks at
  paths with no network and paths in the networks the node belongs to (its
  `NetworkContextProvider`); `BestPathInNetwork` looks at one network.
- **Refresh.** `Start` runs a loop that, every 45 seconds give or take 15,
  decays the damping penalties and re-advertises every unsuppressed path this
  node originated, so a peer that joins later still learns them.

## Use

```sh
go get github.com/bbmumford/route
```

```go
r, err := route.NewRouter(route.Config{
	NodeID:  route.NodeID(nodeID), // the vl1_ fingerprint of priv's public key
	PrivKey: priv,                 // ed25519.PrivateKey
})
if err != nil {
	return err
}
r.(interface {
	SetPublisher(route.AdvertisementPublisher)
}).SetPublisher(pub) // pub puts advertisements on your fabric
go r.Start(ctx)

// A directly connected peer: no hops.
_ = r.Advertise(peer, nil, "")

// Advertisements from other nodes, as your fabric delivers them.
_ = r.IngestAdvertisement(ad)

if p := r.BestPath(target); p != nil {
	next := p.NextHop // the first hop towards target
	_ = next
}
```

`AllPaths` lists, in selection order, every held path to a target that
`BestPath` could choose (fleet-wide paths and paths in the node's networks), `Withdraw`
originates a withdrawal, and `SetTransitMode` records the node's transit
policy (`TransitNone`, `TransitOptIn`, `TransitFull`). The router returned by
`NewRouter` also has `Stats`, the counters of its `Advertise` calls (locally
ingested, suppressed, skipped for want of a publisher, publish errors).
`proto/pb` holds the protobuf messages generated from `proto/route.proto`; the
router itself works on the Go structs in this package and leaves the wire
encoding to its caller.

## Dependencies

- No other package of this estate.
- `google.golang.org/protobuf`, for the generated `proto/pb` package only.

## Used by

Importers in the ORBTR estate:

- `github.com/bbmumford/loom/node`: `InitRoute` builds a router on the node's
  swarm fabric, publishes its advertisements on the `fleet.route` topic as JSON
  and feeds the records it receives back into the router.
- `github.com/ORBTR/agent/internal/core/wire`: the device agent's mesh wiring.
- `github.com/ORBTR/help.orbtr.io`: its monitoring API reports `BestPath` and
  `Stats`.

## Platforms and build

Pure Go, no cgo and no build tags. The module's `go` directive is 1.25.0.

## Licence

MIT. Copyright (c) 2026 Brandon Miller-Mumford. The full text is in
[LICENSE](LICENSE).

## Contributing

[AGENTS.md](AGENTS.md) holds the repository's two rules, for people and coding
agents alike: no temporary documents in the repository, and conventional commit
messages that stand on their own. [CLAUDE.md](CLAUDE.md) imports it for Claude
Code.
