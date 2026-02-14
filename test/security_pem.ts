import { describe, it, expect } from "vitest";
import { PemConverter } from "../src";

describe("PEM Security", () => {
  it("should not be vulnerable to ReDoS in header parsing", () => {
    const start = Date.now();
    const n = 50000;
    const spaces = " ".repeat(n);
    const payload = `-----BEGIN CERTIFICATE-----
Header: Value
${spaces}
-----END CERTIFICATE-----`;

    // This should take milliseconds, not seconds
    PemConverter.isPem(payload);
    const end = Date.now();
    const duration = end - start;

    expect(duration).toBeLessThan(1000);
  });

  it("should correctly parse continuation lines with single space", () => {
    // AAAA is valid base64
    const pem = `-----BEGIN TEST-----
Key: Value
 Continued
AAAA
-----END TEST-----`;
    const res = PemConverter.decodeWithHeaders(pem);
    expect(res.length).toBe(1);
    expect(res[0].headers[0].key).toBe("Key");
    expect(res[0].headers[0].value).toBe("ValueContinued");
  });

  it("should correctly parse continuation lines with multiple spaces", () => {
    const pem = `-----BEGIN TEST-----
Key: Value
   Continued
AAAA
-----END TEST-----`;
    const res = PemConverter.decodeWithHeaders(pem);
    expect(res.length).toBe(1);
    expect(res[0].headers[0].value).toBe("ValueContinued");
  });
});
