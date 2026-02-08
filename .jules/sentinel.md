## 2024-05-22 - [Enforcing Basic Constraints for V3 CAs]
**Vulnerability:** X509ChainBuilder allowed V3 certificates without BasicConstraints to act as CAs, violating RFC 5280.
**Learning:** Legacy tests were creating invalid V3 CA certificates (missing BasicConstraints), which concealed the vulnerability. When hardening validation logic, expect existing "valid" tests to fail if they rely on the permissive behavior.
**Prevention:** Always enforce strict RFC compliance for certificate extensions, especially for critical roles like CA. Ensure test data generators produce spec-compliant certificates.
