import { Crypto } from "@peculiar/webcrypto";
import {
  describe, it, expect, beforeAll,
} from "vitest";
import {
  X509CertificateGenerator,
  X509ChainBuilder,
  BasicConstraintsExtension,
  KeyUsagesExtension,
  KeyUsageFlags,
  cryptoProvider,
} from "../src";

describe("Security: Basic Constraints Validation", () => {
  beforeAll(() => {
    const crypto = new Crypto();
    cryptoProvider.set(crypto);
  });

  it("should REJECT an intermediate certificate that is missing Basic Constraints extension (v3)", async () => {
    const crypto = cryptoProvider.get();

    // 1. Root CA
    const rootAlg = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };
    const rootKeys = await crypto.subtle.generateKey(rootAlg, true, ["sign", "verify"]);
    const rootCert = await X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=Root CA",
      notBefore: new Date("2020/01/01"),
      notAfter: new Date("2030/01/01"),
      signingAlgorithm: rootAlg,
      keys: rootKeys,
      extensions: [
        new BasicConstraintsExtension(true, undefined, true),
        new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
      ],
    });

    // 2. Intermediate CA (Missing Basic Constraints)
    // RFC 5280: If Basic Constraints is missing in v3, it is NOT a CA.
    const interAlg = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };
    const interKeys = await crypto.subtle.generateKey(interAlg, true, ["sign", "verify"]);
    const interCert = await X509CertificateGenerator.create({
      serialNumber: "02",
      subject: "CN=Intermediate CA",
      issuer: "CN=Root CA",
      notBefore: new Date("2020/01/01"),
      notAfter: new Date("2030/01/01"),
      signingAlgorithm: rootAlg,
      signingKey: rootKeys.privateKey,
      publicKey: interKeys.publicKey,
      extensions: [
        // Intentionally missing BasicConstraintsExtension
        new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
      ],
    });

    // 3. Leaf Certificate
    const leafAlg = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };
    const leafKeys = await crypto.subtle.generateKey(leafAlg, true, ["sign", "verify"]);
    const leafCert = await X509CertificateGenerator.create({
      serialNumber: "03",
      subject: "CN=Leaf",
      issuer: "CN=Intermediate CA",
      notBefore: new Date("2020/01/01"),
      notAfter: new Date("2030/01/01"),
      signingAlgorithm: interAlg,
      signingKey: interKeys.privateKey,
      publicKey: leafKeys.publicKey,
      extensions: [
        new BasicConstraintsExtension(false, undefined, true),
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
      ],
    });

    // Build chain
    const chainBuilder = new X509ChainBuilder({ certificates: [rootCert, interCert] });

    const chain = await chainBuilder.build(leafCert);

    // The chain should NOT include the Intermediate CA because it's invalid as an issuer.
    // It should only contain the leaf certificate itself (failed to find issuer).
    // Or if it strictly validates, it might throw,
    // but X509ChainBuilder seems to just return the list of found certs.

    // If chain length is 3, it means it accepted Intermediate as CA.
    expect(chain.length).toBe(1); // Should fail to find a valid issuer for Leaf
  });
});
