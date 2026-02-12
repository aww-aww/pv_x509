## 2024-05-22 - X509ChainBuilder Performance Optimization
**Learning:** Checking for circular dependencies in certificate chains was O(N^2) due to repeated thumbprint calculation and linear search. `getThumbprint` is an expensive async crypto operation.
**Action:** Always cache expensive crypto digest results on immutable objects. Use `Set` for O(1) lookups instead of array iteration when checking for existence (e.g., circular dependencies).
