import {
  describe, it, expect,
} from "vitest";
import { PemConverter } from "../src";

describe("PEM ReDoS", () => {
  it("should not be vulnerable to ReDoS", () => {
    const base = "-----BEGIN CERTIFICATE-----\nHeader: Value\n";
    const evilPart = " ";
    const suffix = "\n-----END CERTIFICATE-----";

    // Generate a long header with many spaces
    const len = 50000;
    const str = base + evilPart.repeat(len) + suffix;

    const start = process.hrtime();
    PemConverter.decodeWithHeaders(str);
    const diff = process.hrtime(start);
    const timeMs = (diff[0] * 1e9 + diff[1]) / 1e6;

    // With the fix, this should be extremely fast (< 10ms usually).
    // Without the fix, 50,000 would take forever (since 30,000 took > 1s).
    // Let's set a generous limit of 100ms to avoid flakiness in CI.
    expect(timeMs).toBeLessThan(100);
  });
});
