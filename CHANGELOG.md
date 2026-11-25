# Changelog

## [0.1.0](https://github.com/bbmumford/route/compare/v0.0.3...v0.1.0) (2026-11-25)


### ⚠ BREAKING CHANGES

* the field names in route.proto's descriptor change: rtt_sample_ms -> rttSampleMs, issued_at -> issuedAt, node_id_signature -> nodeIdSignature, path_key_signature -> pathKeySignature, pub_key -> pubKey, last_flap -> lastFlap. A reader that names these fields in text format or looks one up by its descriptor name uses the new names.

### Features

* route's proto fields are named in lowerCamelCase, the names protojson already writes ([94b3476](https://github.com/bbmumford/route/commit/94b34769d565daf52bc33d75c087873f649f8a56))


### Bug Fixes

* a receiver counts a flap only when a path returns after a withdrawal or its hops or RTT change, so it no longer suppresses a stable path its origin refreshes ([7d9b629](https://github.com/bbmumford/route/commit/7d9b62905989e733f85ea6ed60cf29e02db5148d))
* a router seeds its advertisement epoch from the wall clock, so a restarted origin's advertisements and withdrawals order after its previous incarnation's and are no longer refused as stale ([4bdb243](https://github.com/bbmumford/route/commit/4bdb243bed05be8ed79920d95251a3d2bccf85fc))
* AllPaths lists only the paths BestPath can choose from ([e54e002](https://github.com/bbmumford/route/commit/e54e0020aa0d881dc27276f34c4f200c7578e940))
* an advertisement carries its per-path public key and both of its signatures are checked ([931f1ac](https://github.com/bbmumford/route/commit/931f1ac449a27364cf1fabd56d910abd336a6a69))
* an origin's re-advertisement carries the communities its advertisement did ([99c548a](https://github.com/bbmumford/route/commit/99c548a8075ff0e67e870f41a4c9c1ba6fce9888))
* BestPath returns a network-scoped path only to a member of that network ([8c92430](https://github.com/bbmumford/route/commit/8c92430287cc983d34ee1e7a08fec7e0cba7ad2a))
* Start and Stop are synchronised, and a Stop before Start stops the router ([7c52302](https://github.com/bbmumford/route/commit/7c52302ab0231dab81141ab1e44d48dc4a79b90c))
* the damping state of a key with no path and no penalty is evicted once quiet, and a message past that retention is stale ([d839aaa](https://github.com/bbmumford/route/commit/d839aaaa7dd9f9760f621223bc2a41ac23a13330))
