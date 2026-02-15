## 2025-02-18 - X509ChainBuilder Circular Dependency Optimization
**Learning:** Checking for circular dependencies in a certificate chain by iterating through the existing chain for every new certificate results in O(N^2) complexity. Using a `Set<string>` of hex-encoded thumbprints reduces this to O(N).
**Action:** When detecting duplicates or cycles in a sequence, prefer using a `Set` for O(1) lookups instead of nested loops. Ensure complex objects (like ArrayBuffers) are converted to primitive strings (like Hex) for Set keys.
