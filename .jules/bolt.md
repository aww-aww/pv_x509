## 2025-02-13 - [Uncached Crypto Operations in Loops]
**Learning:** `X509Certificate.getThumbprint` re-computes the hash on every call. In `X509ChainBuilder`, this caused O(N^2) complexity for circular dependency checks, which became a bottleneck for longer chains (e.g., >100 certs).
**Action:** When working with cryptographic operations (like hashing) inside loops, always check if the result is cached. If not, cache it locally or use efficient data structures like `Set` to avoid redundant computations.
