# Bolt's Journal

## 2025-02-19 - X509Certificate Thumbprint Cost
**Learning:** `X509Certificate.getThumbprint()` always recalculates the hash from raw data upon invocation and does not cache the result internally. This makes repeated calls expensive, especially in loops like chain building.
**Action:** When using `getThumbprint()` in loops or repeatedly for the same certificate, cache the result or use a data structure (like a Set of hex strings) to avoid redundant recalculations.
