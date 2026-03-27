## 2025-02-19 - Regex Performance in TypeScript
**Learning:** Reusing a `RegExp` instance with the global flag (`g`) instead of re-instantiating it can provide significant performance gains (e.g., ~30% in `isPem`), but requires careful manual management of `lastIndex = 0` to prevent state leakage between calls.
**Action:** When optimizing hot paths involving regexes, hoist `RegExp` creation to module scope and explicitly reset `lastIndex` before use.

## 2025-02-19 - String Split Optimization
**Learning:** `String.prototype.split('\n')` is faster than `String.prototype.split(new RegExp('\\n', 'g'))` when the separator is simple and the string is already normalized (e.g., CRLF replaced with LF).
**Action:** Prefer string literals over RegExp for `split` operations when possible, especially after normalization.
