# route

BGP-style path advertisement and best-path selection for the HSTLES fleet
mesh and the ORBTR agent mesh.

## Capabilities

- **PathAdvertisement** — dual-signed records (NodeID + per-path key) advertising
  reachable peers + AS-path-style hop sequences with community tags
- **Best-path selector** — RFC4271 §9.1 simplified: prefer lowest hop count,
  then lowest RTT, then lexicographic NodeID for deterministic tie-break
- **RFC2439 damping** — flap-damping for unstable paths (penalty accumulation,
  suppress/reuse thresholds)
- **Forwarding table** — fast `BestPath(target)` lookup
- **Network scoping** — multi-network agent fabric: filter candidates by
  network membership

