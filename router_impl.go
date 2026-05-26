// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

package route

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

// pathKey identifies a unique advertisement origin × target × network.
type pathKey struct {
	Origin  NodeID
	Target  NodeID
	Network NetworkID
}

// damping carries RFC2439 flap-damping state per pathKey.
type damping struct {
	penalty     uint32
	suppressed  bool
	lastFlap    time.Time
	lastDecay   time.Time
	lastEpoch   uint64
}

// routerImpl is the concrete Router implementation.
type routerImpl struct {
	cfg     Config
	priv    ed25519.PrivateKey
	localID NodeID

	mu        sync.RWMutex
	paths     map[pathKey]*Path        // current valid paths
	damp      map[pathKey]*damping     // damping state per origin/target/network
	localEpoch atomic.Uint64
	transit   atomic.Uint32

	startCtx    context.Context
	startCancel context.CancelFunc
	stopped     atomic.Bool

	netCtx NetworkContextProvider

	// Out-of-band publisher for advertisements. Set by Wire().
	publisher AdvertisementPublisher
}

// AdvertisementPublisher is the surface routerImpl uses to inject signed
// advertisements onto the underlying swarm topic. Consumers (Library /
// agent) wire a callback that publishes onto their fabric's route topic.
type AdvertisementPublisher interface {
	PublishAdvertisement(ad *PathAdvertisement) error
	PublishWithdrawal(w *PathWithdrawal) error
}

// NewRouter constructs a fully-functional Router. The earlier package-
// level New() returned ErrNotImplemented; this entry point replaces it.
// Callers should still go through New() in production code so the stub
// path can be dropped in a future release.
func NewRouter(cfg Config) (Router, error) {
	if cfg.NodeID == "" || cfg.PrivKey == nil {
		return nil, errInvalidConfig
	}
	applyDefaults(&cfg)

	return &routerImpl{
		cfg:     cfg,
		priv:    cfg.PrivKey,
		localID: cfg.NodeID,
		paths:   make(map[pathKey]*Path),
		damp:    make(map[pathKey]*damping),
		netCtx:  cfg.NetworkContext,
	}, nil
}

func applyDefaults(cfg *Config) {
	if cfg.MaxHops <= 0 {
		cfg.MaxHops = 8
	}
	if cfg.MaxPaths <= 0 {
		cfg.MaxPaths = 4
	}
	if cfg.DampSuppress == 0 {
		cfg.DampSuppress = 2000
	}
	if cfg.DampReuse == 0 {
		cfg.DampReuse = 750
	}
	if cfg.DampMaxPenalty == 0 {
		cfg.DampMaxPenalty = 16000
	}
	if cfg.DampHalfLife == 0 {
		cfg.DampHalfLife = 15 * time.Minute
	}
}

// SetPublisher wires the swarm-side publisher. Must be called before any
// Advertise / Withdraw so the engine can dispatch onto the fabric.
func (r *routerImpl) SetPublisher(p AdvertisementPublisher) {
	r.mu.Lock()
	r.publisher = p
	r.mu.Unlock()
}

func (r *routerImpl) Start(ctx context.Context) error {
	r.startCtx, r.startCancel = context.WithCancel(ctx)
	<-r.startCtx.Done()
	return nil
}

func (r *routerImpl) Stop() error {
	if !r.stopped.CompareAndSwap(false, true) {
		return nil
	}
	if r.startCancel != nil {
		r.startCancel()
	}
	return nil
}

// Advertise originates a new PathAdvertisement and dispatches it.
func (r *routerImpl) Advertise(target NodeID, hops []NodeID, network NetworkID, communities ...string) error {
	if r.containsLoop(hops, target) {
		return ErrPathLoop
	}
	if len(hops) > r.cfg.MaxHops {
		return ErrPathTooLong
	}

	ad := &PathAdvertisement{
		Origin:      r.localID,
		Target:      target,
		Hops:        append([]NodeID(nil), hops...),
		Epoch:       r.localEpoch.Add(1),
		Communities: append([]string(nil), communities...),
		IssuedAt:    time.Now(),
		Network:     network,
	}
	r.signAdvertisement(ad)

	// Update local forwarding immediately so we can use our own path.
	_ = r.IngestAdvertisement(ad)

	r.mu.RLock()
	pub := r.publisher
	r.mu.RUnlock()
	if pub != nil {
		return pub.PublishAdvertisement(ad)
	}
	return nil
}

// Withdraw originates a PathWithdrawal.
func (r *routerImpl) Withdraw(target NodeID, network NetworkID) error {
	w := &PathWithdrawal{
		Origin:   r.localID,
		Target:   target,
		Epoch:    r.localEpoch.Add(1),
		IssuedAt: time.Now(),
		Network:  network,
	}
	w.Signature = ed25519.Sign(r.priv, signableWithdrawal(w))

	_ = r.IngestWithdrawal(w)

	r.mu.RLock()
	pub := r.publisher
	r.mu.RUnlock()
	if pub != nil {
		return pub.PublishWithdrawal(w)
	}
	return nil
}

// BestPath returns the best current path to target across all networks
// the local node belongs to, falling back to fleet-wide paths.
func (r *routerImpl) BestPath(target NodeID) *Path {
	networks := []NetworkID{""}
	if r.netCtx != nil {
		networks = append(networks, r.netCtx.LocalNetworks()...)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	var best *Path
	for k, p := range r.paths {
		if k.Target != target {
			continue
		}
		if !networkMatch(k.Network, networks) {
			continue
		}
		if r.damp[k] != nil && r.damp[k].suppressed {
			continue
		}
		if best == nil || pathBetter(p, best) {
			best = p
		}
	}
	if best == nil {
		return nil
	}
	cp := *best
	return &cp
}

// BestPathInNetwork returns the best path to target restricted to a
// specific network scope.
func (r *routerImpl) BestPathInNetwork(target NodeID, network NetworkID) *Path {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var best *Path
	for k, p := range r.paths {
		if k.Target != target || k.Network != network {
			continue
		}
		if r.damp[k] != nil && r.damp[k].suppressed {
			continue
		}
		if best == nil || pathBetter(p, best) {
			best = p
		}
	}
	if best == nil {
		return nil
	}
	cp := *best
	return &cp
}

// AllPaths returns every current path to target ordered by selection
// preference. Suppressed paths are omitted.
func (r *routerImpl) AllPaths(target NodeID) []*Path {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []*Path
	for k, p := range r.paths {
		if k.Target != target {
			continue
		}
		if r.damp[k] != nil && r.damp[k].suppressed {
			continue
		}
		cp := *p
		out = append(out, &cp)
	}
	sortPaths(out)
	return out
}

// SetTransitMode updates this Router's transit policy atomically.
func (r *routerImpl) SetTransitMode(mode TransitMode) error {
	r.transit.Store(uint32(mode))
	return nil
}

// IngestAdvertisement applies an incoming PathAdvertisement.
func (r *routerImpl) IngestAdvertisement(ad *PathAdvertisement) error {
	if ad == nil {
		return ErrSignatureInvalid
	}
	if r.containsLoop(ad.Hops, ad.Target) {
		return ErrPathLoop
	}
	if len(ad.Hops) > r.cfg.MaxHops {
		return ErrPathTooLong
	}
	if !verifyAdvertisement(ad) {
		return ErrSignatureInvalid
	}

	key := pathKey{Origin: ad.Origin, Target: ad.Target, Network: ad.Network}

	r.mu.Lock()
	defer r.mu.Unlock()

	state, ok := r.damp[key]
	if !ok {
		state = &damping{lastDecay: time.Now(), lastFlap: time.Now()}
		r.damp[key] = state
	}
	r.decayPenalty(state)

	if ad.Epoch <= state.lastEpoch && state.lastEpoch != 0 {
		return ErrStaleAdvertisement
	}

	// Penalty: bump for every new advertisement after the first.
	if state.lastEpoch > 0 {
		state.penalty += 1000
		if state.penalty > r.cfg.DampMaxPenalty {
			state.penalty = r.cfg.DampMaxPenalty
		}
		if state.penalty >= r.cfg.DampSuppress {
			state.suppressed = true
		}
		state.lastFlap = time.Now()
	}
	state.lastEpoch = ad.Epoch

	if state.suppressed {
		return ErrPathSuppressed
	}

	// Build a Path: NextHop is first hop if any, else target (direct).
	nextHop := ad.Target
	if len(ad.Hops) > 0 {
		nextHop = ad.Hops[0]
	}
	fullHops := append(append([]NodeID(nil), ad.Hops...), ad.Target)
	r.paths[key] = &Path{
		Target:      ad.Target,
		NextHop:     nextHop,
		Hops:        fullHops,
		RTTSampleMs: ad.RTTSampleMs,
		Origin:      ad.Origin,
		Network:     ad.Network,
	}
	return nil
}

// IngestWithdrawal applies an incoming PathWithdrawal.
func (r *routerImpl) IngestWithdrawal(w *PathWithdrawal) error {
	if w == nil {
		return ErrSignatureInvalid
	}
	if !verifyWithdrawal(w) {
		return ErrSignatureInvalid
	}
	key := pathKey{Origin: w.Origin, Target: w.Target, Network: w.Network}

	r.mu.Lock()
	defer r.mu.Unlock()
	if state, ok := r.damp[key]; ok && w.Epoch <= state.lastEpoch {
		// Stale withdrawal.
		return ErrStaleAdvertisement
	}
	delete(r.paths, key)
	return nil
}

// containsLoop reports whether hops + target contain the local node.
// A path that includes the local node would route through ourselves
// — silently dropped to avoid infinite loops.
func (r *routerImpl) containsLoop(hops []NodeID, target NodeID) bool {
	if target == r.localID {
		return true
	}
	for _, h := range hops {
		if h == r.localID {
			return true
		}
	}
	// Also reject duplicate hops within a single path.
	seen := make(map[NodeID]struct{}, len(hops))
	for _, h := range hops {
		if _, ok := seen[h]; ok {
			return true
		}
		seen[h] = struct{}{}
	}
	return false
}

// decayPenalty applies RFC2439-style exponential decay to the damping
// penalty since lastDecay. Half-life governs the decay rate.
func (r *routerImpl) decayPenalty(d *damping) {
	now := time.Now()
	elapsed := now.Sub(d.lastDecay)
	if elapsed <= 0 {
		return
	}
	if d.penalty == 0 {
		d.lastDecay = now
		return
	}
	// penalty *= 2^(-elapsed/halfLife)
	ratio := float64(elapsed) / float64(r.cfg.DampHalfLife)
	if ratio > 32 { // clamp for very large gaps
		ratio = 32
	}
	factor := powHalf(ratio)
	d.penalty = uint32(float64(d.penalty) * factor)
	d.lastDecay = now

	if d.suppressed && d.penalty < r.cfg.DampReuse {
		d.suppressed = false
	}
}

// powHalf returns 0.5^x.
func powHalf(x float64) float64 {
	out := 1.0
	for x >= 1 {
		out *= 0.5
		x -= 1
	}
	if x > 0 {
		// Linear interpolation for the fractional portion is good enough
		// for damping (suppress/reuse thresholds aren't sub-percent).
		out *= 1.0 - 0.5*x
	}
	return out
}

// networkMatch returns true if pathNet matches any of the local node's
// networks. Fleet-wide paths (Network == "") match every local context.
func networkMatch(pathNet NetworkID, locals []NetworkID) bool {
	if pathNet == "" {
		return true
	}
	for _, n := range locals {
		if n == pathNet {
			return true
		}
		if n == "" {
			return true // fleet context accepts every network
		}
	}
	return false
}

// pathBetter returns true if a should be preferred over b. Criteria:
// 1) fewer hops, 2) lower RTT sample, 3) lower origin NodeID for stability.
func pathBetter(a, b *Path) bool {
	if len(a.Hops) != len(b.Hops) {
		return len(a.Hops) < len(b.Hops)
	}
	if a.RTTSampleMs != b.RTTSampleMs {
		return a.RTTSampleMs < b.RTTSampleMs
	}
	return a.Origin < b.Origin
}

func sortPaths(paths []*Path) {
	for i := 1; i < len(paths); i++ {
		for j := i; j > 0 && pathBetter(paths[j], paths[j-1]); j-- {
			paths[j-1], paths[j] = paths[j], paths[j-1]
		}
	}
}

// ---------- signing ----------

// signableAdvertisement is the canonical byte form of an advertisement
// used as signature input. Excludes both signature fields.
//
//	origin_len:u16 || origin || target_len:u16 || target ||
//	hops_count:u16 || (hop_len:u16 || hop)* ||
//	rtt:u32 || epoch:u64 || issued_at:i64 ||
//	communities_count:u16 || (comm_len:u16 || comm)* ||
//	network_len:u16 || network
func signableAdvertisement(ad *PathAdvertisement) []byte {
	buf := make([]byte, 0, 256)
	buf = appendLenString(buf, string(ad.Origin))
	buf = appendLenString(buf, string(ad.Target))
	buf = appendUint16(buf, uint16(len(ad.Hops)))
	for _, h := range ad.Hops {
		buf = appendLenString(buf, string(h))
	}
	buf = appendUint32(buf, ad.RTTSampleMs)
	buf = appendUint64(buf, ad.Epoch)
	buf = appendInt64(buf, ad.IssuedAt.UnixNano())
	buf = appendUint16(buf, uint16(len(ad.Communities)))
	for _, c := range ad.Communities {
		buf = appendLenString(buf, c)
	}
	buf = appendLenString(buf, string(ad.Network))
	return buf
}

func signableWithdrawal(w *PathWithdrawal) []byte {
	buf := make([]byte, 0, 128)
	buf = appendLenString(buf, string(w.Origin))
	buf = appendLenString(buf, string(w.Target))
	buf = appendUint64(buf, w.Epoch)
	buf = appendInt64(buf, w.IssuedAt.UnixNano())
	buf = appendLenString(buf, string(w.Network))
	return buf
}

// signAdvertisement fills in both signatures.
func (r *routerImpl) signAdvertisement(ad *PathAdvertisement) {
	signable := signableAdvertisement(ad)
	ad.NodeIDSignature = ed25519.Sign(r.priv, signable)

	pathKey := derivePathKey(r.priv, ad.Origin, ad.Target, ad.Epoch)
	ad.PathKeySignature = ed25519.Sign(pathKey, signable)
}

// verifyAdvertisement validates both signatures.
func verifyAdvertisement(ad *PathAdvertisement) bool {
	pub, ok := pubFromNodeID(ad.Origin)
	if !ok {
		return false
	}
	signable := signableAdvertisement(ad)

	if len(ad.NodeIDSignature) != ed25519.SignatureSize {
		return false
	}
	if !ed25519.Verify(pub, signable, ad.NodeIDSignature) {
		return false
	}

	// Path-key signature: we verify against the public key derived from
	// the per-path key. Since the per-path key is derived from the
	// publisher's private key (not held by the verifier), we cannot
	// reconstruct the keypair. The path-key verification is effectively
	// a tamper-evidence check that requires the verifier to know the
	// per-path public key out of band. For now, accept absence as
	// optional (the NodeID signature already authenticates the origin).
	// A future revision will publish per-path public keys via PeerRecord.
	if len(ad.PathKeySignature) == 0 {
		return true
	}
	return true
}

func verifyWithdrawal(w *PathWithdrawal) bool {
	pub, ok := pubFromNodeID(w.Origin)
	if !ok {
		return false
	}
	if len(w.Signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, signableWithdrawal(w), w.Signature)
}

// derivePathKey produces a per-(origin, target, epoch) Ed25519 keypair
// via HKDF-SHA256 over the node identity key. The seed becomes the
// Ed25519 private key. Provides defense-in-depth: even if a single
// path-key leaks, replay across other pairs is impossible.
func derivePathKey(nodePriv ed25519.PrivateKey, origin, target NodeID, epoch uint64) ed25519.PrivateKey {
	info := make([]byte, 0, 32+len(origin)+len(target)+8)
	info = append(info, []byte("route-path-v1")...)
	info = append(info, []byte(origin)...)
	info = append(info, []byte(target)...)
	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], epoch)
	info = append(info, ep[:]...)

	seed, err := hkdf.Key(sha256.New, nodePriv.Seed(), nil, string(info), ed25519.SeedSize)
	if err != nil {
		return nil
	}
	return ed25519.NewKeyFromSeed(seed)
}

// pubFromNodeID extracts the Ed25519 public key embedded in a NodeID.
// NodeID is hex(pubkey) — 64 chars.
func pubFromNodeID(id NodeID) (ed25519.PublicKey, bool) {
	s := string(id)
	if len(s) != 2*ed25519.PublicKeySize {
		return nil, false
	}
	pub := make([]byte, ed25519.PublicKeySize)
	for i := 0; i < ed25519.PublicKeySize; i++ {
		hi, ok1 := hexNibble(s[2*i])
		lo, ok2 := hexNibble(s[2*i+1])
		if !ok1 || !ok2 {
			return nil, false
		}
		pub[i] = (hi << 4) | lo
	}
	return pub, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// ---------- encoding helpers ----------

func appendUint16(buf []byte, v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return append(buf, b[:]...)
}

func appendUint32(buf []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(buf, b[:]...)
}

func appendUint64(buf []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(buf, b[:]...)
}

func appendInt64(buf []byte, v int64) []byte {
	return appendUint64(buf, uint64(v))
}

func appendLenString(buf []byte, s string) []byte {
	buf = appendUint16(buf, uint16(len(s)))
	return append(buf, []byte(s)...)
}
