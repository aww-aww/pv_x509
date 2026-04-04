## 2025-02-12 - Header Injection in PEM Encoding
**Vulnerability:** PEM injection and header manipulation vulnerability in `PemConverter.encode`.
**Learning:** The PEM encoder blindly concatenated `type`, `header.key`, and `header.value` without validation, allowing attackers to inject arbitrary PEM headers or even forge entire PEM blocks by embedding newlines and PEM boundary markers (e.g., `-----END CERTIFICATE-----`).
**Prevention:** Always validate and sanitize inputs when generating structured text formats like PEM. Specifically, disallow control characters (newlines) and delimiters (colons) in keys and values unless properly escaped or folded according to the format specification.
