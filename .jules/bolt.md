## 2024-05-22 - [X509ChainBuilder Circular Dependency Check]
**Learning:** The circular dependency check in `X509ChainBuilder.build` was O(N^2) due to nested iteration and redundant thumbprint recalculation. This significantly impacted chain building performance for long chains.
**Action:** Use a `Set<string>` (hex thumbprints) for O(1) lookup and O(N) overall complexity for circular dependency detection.
