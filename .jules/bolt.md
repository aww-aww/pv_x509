## 2025-02-12 - [Performance] Cache X509Certificate Thumbprints
**Learning:** `X509Certificate.getThumbprint()` was re-calculating the hash on every call, which is expensive (crypto operation). Caching the result based on the algorithm name significantly improves performance for repeated calls (e.g. 70x speedup in synthetic benchmark).
**Action:** When working with immutable data that requires expensive computation (like cryptographic digests), always consider caching the result if it's likely to be accessed multiple times. Ensure cache keys are normalized (e.g. algorithm names).
