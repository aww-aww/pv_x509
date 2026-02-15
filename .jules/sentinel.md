## 2025-02-18 - Ambiguous PEM Header Regex
**Vulnerability:** `src/pem_converter.ts` used a permissive regex `[^:\n]+` for header keys, which allowed keys to start with spaces. This overlapped with the continuation line pattern ` +[^\n]+\n`, creating ambiguity and potential ReDoS vectors when parsing crafted PEM files.
**Learning:** Overly permissive regexes in parsers, especially those defining structural elements like headers, can lead to ambiguity and denial of service. The parser should strictly enforce the grammar (e.g., keys must not start with whitespace).
**Prevention:** Define regexes as strictly as possible. For headers, explicitly disallow whitespace at the start if that distinguishes them from continuation lines.
