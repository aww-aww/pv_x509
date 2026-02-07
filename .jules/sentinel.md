## 2025-01-20 - Improper Certificate Validation (Missing Basic Constraints Check for V3)
**Vulnerability:** The `X509ChainBuilder` was accepting X.509 Version 3 certificates as valid issuers even if they lacked the `BasicConstraints` extension (or had `cA=false` implicitly due to missing extension). RFC 5280 strictly requires V3 CA certificates to have `BasicConstraints` with `cA=true`.
**Learning:** The library defaulted to permissive validation for V3 certificates missing extensions, likely inheriting behavior from V1/V2 support or simply missing the check. Tests were also generating non-compliant V3 CAs.
**Prevention:** Enforce strict RFC 5280 checks for V3 certificates. Ensure test data generation produces compliant certificates (e.g., adding `BasicConstraints: cA=true` for all CAs).
