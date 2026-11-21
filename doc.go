// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
// Queries: licensing@hstles.com

// Package route implements BGP-style path advertisement and best-path
// selection across the HSTLES fleet mesh and the ORBTR agent mesh.
//
// A PathAdvertisement is a dual-signed record (NodeID + per-path key) that
// advertises a reachable peer plus the AS-path-style hop sequence. Routers
// receive advertisements via the swarm topic layer and maintain a forwarding
// table indexed by target NodeID.
//
// The Router exposes:
//   - Advertise(target, path) — origin a path advertisement
//   - Withdraw(target) — origin a withdrawal
//   - BestPath(target) — query the current best path
//   - BestPathInNetwork(target, network) — agent multi-network variant
//
// Best-path selection follows a simplified RFC4271 §9.1:
//  1. Lowest hop count
//  2. Lowest RTT
//  3. Lexicographically smallest NodeID (deterministic tie-break)
//
// RFC2439 damping is applied to suppress flapping paths.
package route
