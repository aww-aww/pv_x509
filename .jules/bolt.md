## 2025-01-27 - Regex Recompilation in PemConverter
**Learning:** `PemConverter` was re-compiling complex Regex objects in `isPem` and `decodeWithHeaders` methods. Since these methods are static and can be called frequently, this caused significant overhead.
**Action:** Defined Regex objects as module-level constants. When using global flag (`g`), explicitly reset `lastIndex = 0` before use to ensure consistent behavior.
