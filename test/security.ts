
import { describe, it, expect } from "vitest";
import { Convert } from "pvtsutils";
import * as src from "../src";

describe("Security", () => {
  describe("PemConverter", () => {
    it("should prevent header injection via newline in key", () => {
      const maliciousKey = "X-Key\nInjected-Header";
      const params: src.PemStructEncodeParams[] = [
        {
          type: "CERTIFICATE",
          headers: [
            {
              key: maliciousKey,
              value: "value",
            },
          ],
          rawData: Convert.FromUtf8String("data"),
        },
      ];

      expect(() => {
        src.PemConverter.encode(params);
      }).toThrow(/Invalid header key/);
    });

    it("should prevent header injection via colon in key", () => {
        const maliciousKey = "X-Key: value\nInjected-Header";
        const params: src.PemStructEncodeParams[] = [
          {
            type: "CERTIFICATE",
            headers: [
              {
                key: maliciousKey,
                value: "value",
              },
            ],
            rawData: Convert.FromUtf8String("data"),
          },
        ];

        expect(() => {
          src.PemConverter.encode(params);
        }).toThrow(/Invalid header key/);
      });

    it("should prevent header injection via newline in value", () => {
      const maliciousValue = "value\nInjected-Header: malicious";
      const params: src.PemStructEncodeParams[] = [
        {
          type: "CERTIFICATE",
          headers: [
            {
              key: "X-Key",
              value: maliciousValue,
            },
          ],
          rawData: Convert.FromUtf8String("data"),
        },
      ];

      expect(() => {
        src.PemConverter.encode(params);
      }).toThrow(/Invalid header value/);
    });

    it("should prevent header injection via CRLF in value", () => {
        const maliciousValue = "value\r\nInjected-Header: malicious";
        const params: src.PemStructEncodeParams[] = [
          {
            type: "CERTIFICATE",
            headers: [
              {
                key: "X-Key",
                value: maliciousValue,
              },
            ],
            rawData: Convert.FromUtf8String("data"),
          },
        ];

        expect(() => {
          src.PemConverter.encode(params);
        }).toThrow(/Invalid header value/);
      });
  });
});
