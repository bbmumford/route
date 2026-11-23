// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package route

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"
)

// NodeID is an opaque per-peer identifier (Ed25519 public key hex-encoded).
type NodeID string

// NetworkID identifies a per-tenant network overlay. Empty = unscoped (fleet).
type NetworkID string

// PathAdvertisement is the wire representation of a route advertisement.
// Dual-signed: NodeIDSignature (signed by Origin's node identity) AND
// PathKeySignature (signed by a per-path key derived via
// HKDF-SHA256(node-identity, "route-path-v1" || Origin || Target || Epoch)).
type PathAdvertisement struct {
	Origin      NodeID   // who is advertising
	Target      NodeID   // the destination peer
	Hops        []NodeID // intermediate NodeIDs (excludes origin + target)
	RTTSampleMs uint32   // observed RTT from origin to target via this path
	Epoch       uint64   // advertisement epoch (monotonic per Origin)
	Communities []string // tag-style metadata (e.g. "relay:tier2", "transit:full")
	IssuedAt    time.Time
	Network     NetworkID // network scope (empty = fleet-wide)

	NodeIDSignature  []byte // Ed25519 over wire-format excluding signatures
	PathKeySignature []byte // Ed25519 over same envelope, by per-path key

	// PubKey is the Origin's Ed25519 public key. Required because the
	// codebase's NodeIDs are one-way SHA-256 fingerprints (vl1_<hex>) —
	// the verifier cannot derive the public key from the NodeID alone.
	// Stamped by signAdvertisement BEFORE the signature input is computed
	// so signableAdvertisement covers PubKey (closes the rebind attack).
	PubKey []byte
}

// PathWithdrawal removes a previously-advertised path. Sent when Origin
// detects Target is unreachable via this advertised path.
type PathWithdrawal struct {
	Origin    NodeID
	Target    NodeID
	Epoch     uint64 // matches the withdrawn advertisement's epoch
	IssuedAt  time.Time
	Network   NetworkID
	Signature []byte // Ed25519 over wire-format
	PubKey    []byte // Origin's Ed25519 public key — see PathAdvertisement.PubKey
}

// Path represents a selected path in the forwarding table. Not a wire format.
type Path struct {
	Target      NodeID
	NextHop     NodeID   // who to dial first; if equal to Target this is a direct path
	Hops        []NodeID // full path including target
	RTTSampleMs uint32
	Origin      NodeID
	Network     NetworkID
}

// TransitMode controls how this Router participates in transit forwarding.
type TransitMode uint8

const (
	TransitNone  TransitMode = iota // do not forward for others
	TransitOptIn                    // forward only for explicitly allowed peers (edge nodes)
	TransitFull                     // forward for all peers in same tenant (anchor / relay)
)

// Router is the public route API.
type Router interface {
	// Start runs the router until ctx is cancelled or Stop is called. A
	// Start after Stop returns at once.
	Start(ctx context.Context) error

	// Stop shuts down the engine. Idempotent.
	Stop() error

	// Advertise originates a PathAdvertisement with this node as Origin.
	// Signs the envelope (NodeID + per-path key) and publishes via the
	// swarm route topic.
	Advertise(target NodeID, hops []NodeID, network NetworkID, communities ...string) error

	// Withdraw originates a PathWithdrawal for the given target.
	Withdraw(target NodeID, network NetworkID) error

	// BestPath returns the current best path to target (or nil if none).
	BestPath(target NodeID) *Path

	// BestPathInNetwork returns the best path to target restricted to the
	// given network. Used by agent multi-network fabric.
	BestPathInNetwork(target NodeID, network NetworkID) *Path

	// AllPaths returns every current path to target, ordered by selection
	// preference. Useful for debugging and for callers that want fallback.
	AllPaths(target NodeID) []*Path

	// SetTransitMode atomically updates this Router's transit policy.
	SetTransitMode(mode TransitMode) error

	// IngestAdvertisement applies an incoming advertisement from the swarm.
	// Verifies dual signature, applies RFC2439 damping, updates forwarding.
	IngestAdvertisement(ad *PathAdvertisement) error

	// IngestWithdrawal applies an incoming withdrawal.
	IngestWithdrawal(w *PathWithdrawal) error
}

// Config configures a Router.
type Config struct {
	NodeID         NodeID
	PrivKey        ed25519.PrivateKey
	Transit        TransitMode
	MaxHops        int           // default 8
	MaxPaths       int           // default 4 paths per target
	DampSuppress   uint32        // RFC2439 suppress threshold (default 2000)
	DampReuse      uint32        // RFC2439 reuse threshold (default 750)
	DampMaxPenalty uint32        // RFC2439 max penalty (default 16000)
	DampHalfLife   time.Duration // RFC2439 half-life (default 15min)
	NetworkContext NetworkContextProvider
}

// NetworkContextProvider answers "what networks is this local node a member of?"
// Returns empty for fleet; agent populates from IPAM.
type NetworkContextProvider interface {
	LocalNetworks() []NetworkID
}

// New creates a Router. Returned Router is not started. Delegates to
// NewRouter — this entry point exists so callers don't need to track
// the deprecation of the previous stub return.
func New(cfg Config) (Router, error) {
	return NewRouter(cfg)
}

var (
	ErrNotImplemented     = errors.New("route: not implemented")
	ErrSignatureInvalid   = errors.New("route: signature verification failed")
	ErrPathLoop           = errors.New("route: path contains loop")
	ErrPathTooLong        = errors.New("route: path exceeds MaxHops")
	ErrStaleAdvertisement = errors.New("route: advertisement epoch is stale")
	ErrPathSuppressed     = errors.New("route: path is currently suppressed by damping")
	errInvalidConfig      = errors.New("route: invalid config (NodeID and PrivKey required)")
)
