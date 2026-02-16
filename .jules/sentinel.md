## 2025-02-18 - PEM Header Injection
**Vulnerability:** Found that `PemConverter.encode` blindly concatenated header keys and values, allowing newlines in values to inject arbitrary headers or break PEM structure. Additionally, `PemConverter.decodeWithHeaders` incorrectly parsed continuation lines containing colons as new headers.
**Learning:** PEM headers (RFC 1421 style) are legacy but still supported. The library's parser was too lenient and the encoder was naive about input safety.
**Prevention:** Always validate inputs that are used to construct structured text formats. For PEM headers, keys must not contain colons or newlines, and values must be folded (indented) if they span multiple lines. Parsers must strictly respect indentation rules for continuation lines.
