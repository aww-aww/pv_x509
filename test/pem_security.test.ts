
import { describe, it, expect } from "vitest";
import { PemConverter } from "../src/pem_converter";

describe("PemConverter Security", () => {
  it("should prevent header injection via newlines in value", () => {
    const maliciousStruct = {
      type: "CERTIFICATE",
      headers: [
        { key: "Subject", value: "CN=User\nAdmin: true" }
      ],
      rawData: new Uint8Array([1, 2, 3])
    };

    const encoded = PemConverter.encode([maliciousStruct]);
    console.log("Encoded PEM (safe):");
    console.log(encoded);

    // Parse it back to see what happened
    const decoded = PemConverter.decodeWithHeaders(encoded);

    // The injected header "Admin" should NOT be present as a separate header
    const injected = decoded[0].headers.find(h => h.key === "Admin");
    expect(injected).toBeUndefined();

    // The Subject header should contain the multi-line value
    const subject = decoded[0].headers.find(h => h.key === "Subject");
    expect(subject).toBeDefined();
    // decodeWithHeaders joins continuation lines (without space if trimmed?)
    // Wait, decodeWithHeaders: lastHeader.value += key.trim();
    // "Admin: true" starts with space in encoded PEM (due to fix).
    // key is " Admin: true". key.trim() is "Admin: true".
    // So value should be "CN=UserAdmin: true".
    expect(subject?.value).toBe("CN=UserAdmin: true");
  });

  it("should throw error if type contains newlines", () => {
    const badType = {
      type: "CERTIFICATE\nBAD",
      rawData: new Uint8Array([1])
    };
    expect(() => PemConverter.encode([badType])).toThrow("PEM type cannot contain newlines");
  });

  it("should throw error if header key contains newlines", () => {
    const badKey = {
      type: "CERTIFICATE",
      headers: [{ key: "Key\nInjection", value: "val" }],
      rawData: new Uint8Array([1])
    };
    expect(() => PemConverter.encode([badKey])).toThrow("PEM header key cannot contain newlines or colons");
  });

  it("should throw error if header key contains colons", () => {
    const badKey = {
      type: "CERTIFICATE",
      headers: [{ key: "Key:Injection", value: "val" }],
      rawData: new Uint8Array([1])
    };
    expect(() => PemConverter.encode([badKey])).toThrow("PEM header key cannot contain newlines or colons");
  });

  it("should throw error if header key starts with space", () => {
    const badKey = {
      type: "CERTIFICATE",
      headers: [{ key: " Key", value: "val" }],
      rawData: new Uint8Array([1])
    };
    expect(() => PemConverter.encode([badKey])).toThrow("PEM header key cannot start with space");
  });

  it("should correctly encode multi-line values", () => {
    const struct = {
      type: "NOTE",
      headers: [{ key: "Note", value: "Line 1\nLine 2\nLine 3" }],
      rawData: new Uint8Array([1])
    };
    const encoded = PemConverter.encode([struct]);
    // Expect indentation
    expect(encoded).toContain("Note: Line 1");
    expect(encoded).toContain("\n Line 2");
    expect(encoded).toContain("\n Line 3");
  });
});
