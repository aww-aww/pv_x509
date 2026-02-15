import {
  describe, it, expect,
} from "vitest";
import { PemConverter } from "../src/pem_converter";

describe("Security PEM", () => {
  it("should reject PEM with header starting with space", () => {
    // This input exploits the ambiguity where a line starting with space could be interpreted
    // as a new header if the parser is overly permissive.
    const pem = `-----BEGIN CERTIFICATE-----
 Space: Value
MDSW
-----END CERTIFICATE-----`;

    // Before the fix, this returns true because " Space: Value" is parsed as a header
    // with key " Space".
    // After the fix, this should return false because " Space" is not a valid key start,
    // and " Space: Value" is not a valid continuation line (no previous header).
    const isPem = PemConverter.isPem(pem);
    expect(isPem).toBe(false);
  });

  it("should accept PEM with header key containing internal spaces", () => {
    // Valid header keys might contain spaces internally (though rare/discouraged),
    // but MUST NOT start with a space.
    const pem = `-----BEGIN CERTIFICATE-----
Key with spaces: Value
MDSW
-----END CERTIFICATE-----`;

    const isPem = PemConverter.isPem(pem);
    expect(isPem).toBe(true);
  });

  it("should accept PEM with valid continuation lines", () => {
    const pem = `-----BEGIN CERTIFICATE-----
Key: Value
 Continuation
MDSW
-----END CERTIFICATE-----`;

    const isPem = PemConverter.isPem(pem);
    expect(isPem).toBe(true);
  });
});
