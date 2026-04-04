import {
  describe, it, expect,
} from "vitest";
import * as src from "../src";

describe("PEM Security", () => {
  const rawData = new Uint8Array([1, 2, 3]).buffer;

  describe("encode", () => {
    it("should throw error if type contains newline", () => {
      expect(() => {
        src.PemConverter.encode([{
          type: "CERTIFICATE\nMALICIOUS",
          rawData,
        }]);
      }).toThrow();
    });

    it("should throw error if header key contains newline", () => {
      expect(() => {
        src.PemConverter.encode([{
          type: "CERTIFICATE",
          rawData,
          headers: [
            {
              key: "Header\nName", value: "Value",
            },
          ],
        }]);
      }).toThrow();
    });

    it("should throw error if header key contains colon", () => {
      expect(() => {
        src.PemConverter.encode([{
          type: "CERTIFICATE",
          rawData,
          headers: [
            {
              key: "Header:Name", value: "Value",
            },
          ],
        }]);
      }).toThrow();
    });

    it("should throw error if header key starts with whitespace", () => {
      expect(() => {
        src.PemConverter.encode([{
          type: "CERTIFICATE",
          rawData,
          headers: [
            {
              key: " HeaderName", value: "Value",
            },
          ],
        }]);
      }).toThrow();
    });

    it("should throw error if header value contains newline", () => {
      expect(() => {
        src.PemConverter.encode([{
          type: "CERTIFICATE",
          rawData,
          headers: [
            {
              key: "HeaderName", value: "Value\n-----END CERTIFICATE-----",
            },
          ],
        }]);
      }).toThrow();
    });
  });
});
