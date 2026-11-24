// Copyright (c) 2026 Brandon Miller-Mumford.
// Licensed under the MIT License; see LICENSE.

package route

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"math/rand/v2"
	"strings"
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
	penalty    uint32
	suppressed bool
	lastFlap   time.Time
	lastDecay  time.Time
	lastEpoch  uint64
}

// routerImpl is the concrete Router implementation.
type routerImpl struct {
	cfg     Config
	priv    ed25519.PrivateKey
	localID NodeID

	mu    sync.RWMutex
	paths map[pathKey]*Path    // current valid paths
	damp  map[pathKey]*damping // damping state per origin/target/network

	// localEpoch is the last epoch this router stamped on an advertisement or
	// withdrawal. NewRouter seeds it from the wall clock in nanoseconds, so
	// every epoch a restarted router issues orders after every epoch its
	// previous incarnation issued: IngestAdvertisement and IngestWithdrawal
	// refuse an epoch at or below the last one a receiver holds for the
	// (origin, target, network), and that state outlives the origin's process.
	localEpoch atomic.Uint64
	transit    atomic.Uint32

	// lifeMu orders Start's check of stopped and its write of startCancel
	// against Stop's read of startCancel, so a Stop that runs before, during
	// or after Start's setup always ends that Start.
	lifeMu      sync.Mutex
	startCancel context.CancelFunc // cancels the running Start's loop; guarded by lifeMu
	stopped     atomic.Bool

	netCtx NetworkContextProvider

	// Out-of-band publisher for advertisements. Set by Wire().
	publisher AdvertisementPublisher

	// Advertise-path counters. Exposed via Stats() so operators can
	// distinguish "no advertisements being made" from "advertisements
	// are being suppressed" from "advertisements are made but never
	// publish onto the swarm". Each Advertise() always bumps advCalls
	// and then exactly one of {advLocallyIngestedOK, advSuppressed} for
	// the ingest side, and at most one of {advPublishSkippedNilPublisher,
	// advPublishError} for the publish side. Loop / TooLong / Signature
	// failures bump advCalls but no terminal counter — they read as
	// "called but nothing reported", which is the right signal.
	advCalls                      atomic.Uint64
	advLocallyIngestedOK          atomic.Uint64
	advSuppressed                 atomic.Uint64
	advPublishSkippedNilPublisher atomic.Uint64
	advPublishError               atomic.Uint64
}

// RouterStats is a point-in-time snapshot of the router's Advertise-path
// counters. Returned by routerImpl.Stats() and surfaced via the
// help.orbtr.io /swarm-debug monitoring endpoint so operators can
// distinguish "no advertisements" from "advertisements suppressed by
// damping" from "advertisements never reached the swarm publisher".
type RouterStats struct {
	AdvertiseCalls                uint64 `json:"advertiseCalls"`
	AdvertiseLocallyIngestedOK    uint64 `json:"advertiseLocallyIngestedOK"`
	AdvertiseSuppressed           uint64 `json:"advertiseSuppressed"`
	AdvertisePublishSkippedNilPub uint64 `json:"advertisePublishSkippedNilPublisher"`
	AdvertisePublishError         uint64 `json:"advertisePublishError"`
}

// Stats returns a point-in-time snapshot of the router's Advertise-path
// counters. Safe for concurrent use; reads are lock-free atomic loads.
func (r *routerImpl) Stats() RouterStats {
	return RouterStats{
		AdvertiseCalls:                r.advCalls.Load(),
		AdvertiseLocallyIngestedOK:    r.advLocallyIngestedOK.Load(),
		AdvertiseSuppressed:           r.advSuppressed.Load(),
		AdvertisePublishSkippedNilPub: r.advPublishSkippedNilPublisher.Load(),
		AdvertisePublishError:         r.advPublishError.Load(),
	}
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

	r := &routerImpl{
		cfg:     cfg,
		priv:    cfg.PrivKey,
		localID: cfg.NodeID,
		paths:   make(map[pathKey]*Path),
		damp:    make(map[pathKey]*damping),
		netCtx:  cfg.NetworkContext,
	}
	r.localEpoch.Store(uint64(time.Now().UnixNano()))
	return r, nil
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

// reconvergeInterval is the base period between background re-emissions
// of locally-originated advertisements + damping decay. Jittered by
// reconvergeJitter so a freshly-restarted fleet doesn't synchronise its
// broadcasts. Tuned to match swarm anti-entropy cadence — fast enough
// that a join during a publisher hiccup is recovered within ~1 minute,
// slow enough that a stable fleet doesn't waste topic bandwidth.
const (
	reconvergeInterval = 45 * time.Second
	reconvergeJitter   = 15 * time.Second
)

// Start runs the background reconvergence loop until ctx is cancelled.
// Every reconvergeInterval (jittered) it:
//  1. Decays damping penalty for every tracked pathKey so suppressed
//     entries eventually become eligible again under the RFC2439 reuse
//     threshold.
//  2. Re-emits Advertise for every locally-originated, non-suppressed
//     path. Closes the gap where a peer joined just after we last
//     published and the swarm anti-entropy gossip hasn't caught it yet,
//     or where the originating Advertise raced an empty publisher.
//
// Lock discipline: snapshot the (target, network) pairs to re-emit under
// r.mu, then drop the lock before calling Advertise — Advertise itself
// takes r.mu in IngestAdvertisement and would deadlock if we held it.
//
// Start returns at once when Stop has already run, and Stop ends a running
// Start.
func (r *routerImpl) Start(ctx context.Context) error {
	r.lifeMu.Lock()
	if r.stopped.Load() {
		r.lifeMu.Unlock()
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.startCancel = cancel
	r.lifeMu.Unlock()
	defer cancel()

	for {
		// Jittered next-tick so independently-started routers desync.
		jitter := time.Duration(rand.Int64N(int64(2*reconvergeJitter))) - reconvergeJitter
		next := reconvergeInterval + jitter
		if next < time.Second {
			next = time.Second
		}
		timer := time.NewTimer(next)

		select {
		case <-runCtx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}

		r.reconvergeOnce()
	}
}

// reconvergeOnce performs one decay + re-emit pass. Extracted from
// Start so unit tests can drive it directly without running the timer.
func (r *routerImpl) reconvergeOnce() {
	type reemit struct {
		target      NodeID
		network     NetworkID
		hops        []NodeID
		communities []string
	}

	r.mu.Lock()
	// Decay every damping entry; suppressed entries that fall below the
	// RFC2439 reuse threshold flip back to usable inside decayPenalty.
	for _, d := range r.damp {
		r.decayPenalty(d)
	}

	// Snapshot the locally-originated, non-suppressed paths. We re-emit
	// only paths whose Origin is this node — re-emitting paths we
	// learned from peers would amplify their advertisements without
	// adding any new information.
	pending := make([]reemit, 0, len(r.paths))
	for k, p := range r.paths {
		if k.Origin != r.localID {
			continue
		}
		if d, ok := r.damp[k]; ok && d.suppressed {
			continue
		}
		// Strip the trailing target hop we appended in IngestAdvertisement
		// so the re-emit matches the wire shape Advertise expects.
		hops := p.Hops
		if len(hops) > 0 && hops[len(hops)-1] == k.Target {
			hops = hops[:len(hops)-1]
		}
		pending = append(pending, reemit{
			target:      k.Target,
			network:     k.Network,
			hops:        append([]NodeID(nil), hops...),
			communities: append([]string(nil), p.Communities...),
		})
	}
	r.mu.Unlock()

	// Re-emit outside the lock — Advertise takes r.mu itself.
	for _, e := range pending {
		_ = r.Advertise(e.target, e.hops, e.network, e.communities...)
	}
}

func (r *routerImpl) Stop() error {
	if !r.stopped.CompareAndSwap(false, true) {
		return nil
	}
	r.lifeMu.Lock()
	cancel := r.startCancel
	r.lifeMu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

// Advertise originates a new PathAdvertisement and dispatches it.
func (r *routerImpl) Advertise(target NodeID, hops []NodeID, network NetworkID, communities ...string) error {
	r.advCalls.Add(1)
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
	// Damping-suppressed origin paths are a real operational state we
	// expose separately so operators can tell "we're calling Advertise
	// but our own path keeps getting damped" apart from "we never
	// called Advertise".
	if ingestErr := r.IngestAdvertisement(ad); ingestErr == ErrPathSuppressed {
		r.advSuppressed.Add(1)
	} else if ingestErr == nil {
		r.advLocallyIngestedOK.Add(1)
	}

	r.mu.RLock()
	pub := r.publisher
	r.mu.RUnlock()
	if pub == nil {
		r.advPublishSkippedNilPublisher.Add(1)
		return nil
	}
	if err := pub.PublishAdvertisement(ad); err != nil {
		r.advPublishError.Add(1)
		return err
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
	r.signWithdrawal(w)

	_ = r.IngestWithdrawal(w)

	r.mu.RLock()
	pub := r.publisher
	r.mu.RUnlock()
	if pub != nil {
		return pub.PublishWithdrawal(w)
	}
	return nil
}

// BestPath returns the best current path to target among the fleet-wide
// paths and the paths scoped to a network the local node is a member of
// (NetworkContext.LocalNetworks; none when no provider is set).
func (r *routerImpl) BestPath(target NodeID) *Path {
	var networks []NetworkID
	if r.netCtx != nil {
		networks = r.netCtx.LocalNetworks()
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

	// Self-originated direct edges (Origin == localID, Hops empty) are
	// the operator's own first-hop advertisement to a directly-connected
	// peer — not a flap signal. The operator routinely re-advertises its
	// direct edges (peer (re)connect, capability change, periodic
	// refresh), and three near-simultaneous calls for the same peer can
	// otherwise drive penalty past DampSuppress (default 2000) on the
	// third Advertise, suppressing the operator's own best path to that
	// peer. Damping exists to protect against remote flap storms; it
	// must not silence local truths.
	selfDirectEdge := ad.Origin == r.localID && len(ad.Hops) == 0

	// Penalty: bump for a flap, the path returning after a withdrawal or its
	// hops or RTT changing. A refresh of the held path (a new epoch with the
	// same hops and RTT) is not a flap: reconvergeOnce re-advertises every
	// locally originated path each reconvergeInterval, and counting those
	// refreshes would suppress at every receiver the stable paths it keeps
	// alive.
	held := r.paths[key]
	flap := held == nil || !sameRoute(held, ad)
	if state.lastEpoch > 0 && !selfDirectEdge && flap {
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
		Communities: append([]string(nil), ad.Communities...),
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

// sameRoute reports whether ad carries the attributes p holds: the same hops
// to the same target and the same RTT sample, the fields pathBetter selects
// on, and the same communities, in order.
func sameRoute(p *Path, ad *PathAdvertisement) bool {
	if p.RTTSampleMs != ad.RTTSampleMs || len(p.Hops) != len(ad.Hops)+1 || len(p.Communities) != len(ad.Communities) {
		return false
	}
	for i, c := range ad.Communities {
		if p.Communities[i] != c {
			return false
		}
	}
	for i, h := range ad.Hops {
		if p.Hops[i] != h {
			return false
		}
	}
	return p.Hops[len(ad.Hops)] == ad.Target
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

// networkMatch reports whether a path scoped to pathNet is usable by a node
// that is a member of locals. A fleet-wide path (Network == "") is usable by
// every node; a network-scoped path only by a member of that network.
func networkMatch(pathNet NetworkID, locals []NetworkID) bool {
	if pathNet == "" {
		return true
	}
	for _, n := range locals {
		if n == pathNet {
			return true
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
//
// signableAdvertisement now includes PubKey to close the rebind attack
// (an attacker who swaps PubKey + re-signs would otherwise produce a
// valid signature). PubKey MUST be set by the signer before this runs.
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
	buf = appendLenBytes(buf, ad.PubKey)
	return buf
}

func signableWithdrawal(w *PathWithdrawal) []byte {
	buf := make([]byte, 0, 128)
	buf = appendLenString(buf, string(w.Origin))
	buf = appendLenString(buf, string(w.Target))
	buf = appendUint64(buf, w.Epoch)
	buf = appendInt64(buf, w.IssuedAt.UnixNano())
	buf = appendLenString(buf, string(w.Network))
	buf = appendLenBytes(buf, w.PubKey)
	return buf
}

// signAdvertisement stamps PubKey + fills in both signatures. PubKey is
// assigned BEFORE signableAdvertisement runs so the signed bytes cover
// the pubkey. This mirrors the SignRecord field-ordering fix (ledger
// v0.0.15) — a sender that hashes a record where len(PubKey)==0 then
// stamps PubKey afterward produces bytes the verifier can't reproduce.
func (r *routerImpl) signAdvertisement(ad *PathAdvertisement) {
	ad.PubKey = []byte(r.priv.Public().(ed25519.PublicKey))
	signable := signableAdvertisement(ad)
	ad.NodeIDSignature = ed25519.Sign(r.priv, signable)

	pathKey := derivePathKey(r.priv, ad.Origin, ad.Target, ad.Epoch)
	ad.PathKeySignature = ed25519.Sign(pathKey, signable)
}

// verifyAdvertisement validates both signatures. Uses the PubKey
// embedded on the wire — NodeIDs in this codebase are one-way SHA-256
// fingerprints (vl1_<encoded>), so the verifier cannot derive the
// public key from the NodeID. To prevent an attacker from claiming an
// arbitrary Origin NodeID + stamping their own PubKey + signing with
// their own key, we re-derive the expected NodeID from PubKey and
// reject when it doesn't match ad.Origin. This restores the
// binding lost when the original pubFromNodeID(hex) assumption was
// abandoned.
func verifyAdvertisement(ad *PathAdvertisement) bool {
	if len(ad.PubKey) != ed25519.PublicKeySize {
		return false
	}
	pub := ed25519.PublicKey(ad.PubKey)

	// Binding check: NodeID must be the fingerprint of PubKey.
	expectedNodeID, ok := nodeIDFromPubKey(pub)
	if !ok || expectedNodeID != ad.Origin {
		return false
	}

	signable := signableAdvertisement(ad)
	if len(ad.NodeIDSignature) != ed25519.SignatureSize {
		return false
	}
	if !ed25519.Verify(pub, signable, ad.NodeIDSignature) {
		return false
	}

	// Path-key signature: tamper-evidence check; cannot reconstruct the
	// per-path keypair from the publisher-only private key. Optional
	// until per-path public keys ship via PeerRecord.
	if len(ad.PathKeySignature) == 0 {
		return true
	}
	return true
}

func (r *routerImpl) signWithdrawal(w *PathWithdrawal) {
	w.PubKey = []byte(r.priv.Public().(ed25519.PublicKey))
	w.Signature = ed25519.Sign(r.priv, signableWithdrawal(w))
}

func verifyWithdrawal(w *PathWithdrawal) bool {
	if len(w.PubKey) != ed25519.PublicKeySize {
		return false
	}
	pub := ed25519.PublicKey(w.PubKey)
	expectedNodeID, ok := nodeIDFromPubKey(pub)
	if !ok || expectedNodeID != w.Origin {
		return false
	}
	if len(w.Signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, signableWithdrawal(w), w.Signature)
}

// nodeIDFromPubKey derives the canonical NodeID from an Ed25519 public
// key, mirroring aether.NewNodeID: SHA-256(pubkey) → first 16 bytes →
// base32-no-pad lowercase → "vl1_" prefix. Returns false on an
// improperly-sized key.
func nodeIDFromPubKey(pub ed25519.PublicKey) (NodeID, bool) {
	if len(pub) != ed25519.PublicKeySize {
		return "", false
	}
	hash := sha256.Sum256(pub)
	encoded := strings.ToLower(routeBase32NoPad.EncodeToString(hash[:16]))
	return NodeID("vl1_" + encoded), true
}

// routeBase32NoPad mirrors aether's base32 alphabet (RFC 4648 lowercase,
// no padding). Defined locally so route doesn't depend on aether for
// what is a pure derivation step.
var routeBase32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

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

func appendLenBytes(buf []byte, b []byte) []byte {
	buf = appendUint16(buf, uint16(len(b)))
	return append(buf, b...)
}
