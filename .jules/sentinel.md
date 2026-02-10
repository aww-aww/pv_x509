## 2024-12-07 - [X.509 V3 CA Basic Constraints Validation]
**Vulnerability:** X509ChainBuilder accepted Version 3 certificates as issuers (CAs) even if they were missing the `BasicConstraints` extension. RFC 5280 explicitly mandates that Version 3 CAs must have `BasicConstraints` with `cA=true`.
**Learning:** Default behavior in ASN.1 parsers or high-level libraries might not strictly enforce all RFC constraints unless explicitly checked. Tests relying on loose validation can mask such vulnerabilities.
**Prevention:** Always verify certificate version and enforce extension presence (BasicConstraints) when validating certificate chains, especially for Version 3 certificates. Tests for chain validation should include cases with missing critical extensions.
