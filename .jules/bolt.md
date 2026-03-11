## 2025-05-18 - RegExp Compilation Overhead
**Learning:** Recompiling complex Regular Expressions inside frequent function calls (like `isPem` or `decodeWithHeaders`) incurs significant overhead (~20-30% of execution time). Hoisting them to module-level constants provides a measurable performance boost.
**Action:** Always hoist invariant RegExp objects to module scope, but be careful with the `g` (global) flag and `lastIndex` state—ensure `lastIndex` is reset before use if the regex is shared.

## 2025-05-18 - String Split vs RegExp Split
**Learning:** `String.prototype.split('\n')` was measured to be faster and simpler than `String.prototype.split(/\\n/g)` or `split(new RegExp('\\n', 'g'))` for parsing PEM headers in this environment (Node/Bun).
**Action:** Prefer simple string separators for `split` when possible, as it avoids RegExp engine overhead.
