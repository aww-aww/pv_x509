import { Crypto } from "@peculiar/webcrypto";
import {
  describe, it, expect, beforeAll,
} from "vitest";
import * as x509 from "../src";

describe("X509ChainBuilder Circular Dependency", () => {
  const crypto = new Crypto();
  x509.cryptoProvider.set(crypto);

  let certA: x509.X509Certificate;
  let certB: x509.X509Certificate;

  beforeAll(async () => {
    const alg = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };
    const keysA = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
    const keysB = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);

    // Create Cert A signed by B
    certA = await x509.X509CertificateGenerator.create({
      serialNumber: "01",
      subject: "CN=A",
      issuer: "CN=B",
      notBefore: new Date("2020/01/01"),
      notAfter: new Date("2030/01/01"),
      signingAlgorithm: alg,
      signingKey: keysB.privateKey,
      publicKey: keysA.publicKey,
      extensions: [
        new x509.BasicConstraintsExtension(true, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
      ],
    });

    // Create Cert B signed by A
    certB = await x509.X509CertificateGenerator.create({
      serialNumber: "02",
      subject: "CN=B",
      issuer: "CN=A",
      notBefore: new Date("2020/01/01"),
      notAfter: new Date("2030/01/01"),
      signingAlgorithm: alg,
      signingKey: keysA.privateKey,
      publicKey: keysB.publicKey,
      extensions: [
        new x509.BasicConstraintsExtension(true, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
      ],
    });
  });

  it("should detect circular dependency", async () => {
    const chainBuilder = new x509.X509ChainBuilder({ certificates: [certA, certB] });

    // Start with A. Chain should be A -> B -> A (loop)
    await expect(chainBuilder.build(certA)).rejects.toThrow("Cannot build a certificate chain. Circular dependency.");
  });
});
