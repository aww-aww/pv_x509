## 2025-02-18 - ReDoS in PEM Header Parsing
**Vulnerability:** The regex for parsing PEM headers contained a Regular Expression Denial of Service (ReDoS) vulnerability due to overlapping matches in the continuation line pattern `(?: +[^\n]+\n)*`. An input with many spaces could cause catastrophic backtracking.
**Learning:** Nested quantifiers with overlapping character sets (e.g., ` +` and `[^\n]+` where `[^\n]` includes space) create ambiguity for the regex engine, leading to exponential complexity on failure.
**Prevention:** Use mutually exclusive patterns for parts of the regex. Replaced ` +[^\n]+` with ` [^\n]*`, ensuring the first character is consumed by the space literal and subsequent characters by the negated class, eliminating overlap.
