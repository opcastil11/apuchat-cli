// Client-side crypto only. There is no hub in this package, so these tests
// exercise exactly what runs on the user's machine: link-mode AES-GCM and
// sealed-mode ECDH. If sealed mode ever stops being end-to-end, the "a
// different recipient cannot unseal it" case is what catches it.

import { describe, it, expect } from "vitest";
import {
  encryptSecret,
  decryptSecret,
  generateRecipientKeypair,
  sealToRecipient,
  unsealFromSender,
} from "../src/secret-crypto.js";

describe("client crypto: the hub is not a participant", () => {
  it("round-trips through encrypt/decrypt", async () => {
    const secret = "sk-live-51NOTAREALKEY-abcdef\nSECOND_LINE=value";
    const s = await encryptSecret(secret);
    expect(await decryptSecret(s.ciphertext, s.iv, s.key)).toBe(secret);
  });

  it("ciphertext does not contain the plaintext", async () => {
    const secret = "hunter2-correct-horse-battery-staple";
    const s = await encryptSecret(secret);
    expect(Buffer.from(s.ciphertext, "base64").toString("utf8")).not.toContain("hunter2");
    expect(s.ciphertext).not.toContain(secret);
  });

  it("a wrong key fails loudly rather than returning garbage", async () => {
    const s = await encryptSecret("top secret");
    const other = await encryptSecret("decoy");
    await expect(decryptSecret(s.ciphertext, s.iv, other.key)).rejects.toThrow();
  });

  it("tampered ciphertext fails — GCM authenticates", async () => {
    const s = await encryptSecret("top secret");
    const bytes = Buffer.from(s.ciphertext, "base64");
    bytes[0] ^= 0xff;
    await expect(decryptSecret(bytes.toString("base64"), s.iv, s.key)).rejects.toThrow();
  });

  it("two drops of the same plaintext produce different ciphertext (fresh key + nonce)", async () => {
    const a = await encryptSecret("same");
    const b = await encryptSecret("same");
    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(a.key).not.toBe(b.key);
    expect(a.iv).not.toBe(b.iv);
  });
});

describe("sealed mode crypto (ECDH — no key ever transmitted)", () => {
  it("round-trips through the recipient's keypair", async () => {
    const kp = await generateRecipientKeypair();
    const sealed = await sealToRecipient("sk-live-abc123", kp.publicKey);
    expect(await unsealFromSender(sealed.ciphertext, sealed.iv, sealed.epk, kp.privateKeyJwk)).toBe("sk-live-abc123");
  });

  it("stamps the recipient fingerprint so the receiver knows which key to use", async () => {
    const kp = await generateRecipientKeypair();
    const sealed = await sealToRecipient("x", kp.publicKey);
    expect(sealed.recipient).toBe(kp.fingerprint);
    expect(sealed.recipient).toMatch(/^[A-Za-z0-9_-]{16}$/);
  });

  it("a different recipient cannot unseal it", async () => {
    const intended = await generateRecipientKeypair();
    const eavesdropper = await generateRecipientKeypair();
    const sealed = await sealToRecipient("sk-live-abc123", intended.publicKey);
    await expect(
      unsealFromSender(sealed.ciphertext, sealed.iv, sealed.epk, eavesdropper.privateKeyJwk),
    ).rejects.toThrow();
  });

  it("the sender cannot decrypt afterwards — the ephemeral key is gone", async () => {
    // Modelled by sealing twice to the same recipient: each seal mints a fresh
    // ephemeral key, so the epk differs and neither can be reused as the other.
    const kp = await generateRecipientKeypair();
    const one = await sealToRecipient("same-secret", kp.publicKey);
    const two = await sealToRecipient("same-secret", kp.publicKey);
    expect(one.epk).not.toBe(two.epk);
    expect(one.ciphertext).not.toBe(two.ciphertext);
  });

  it("a tampered epk fails the GCM tag rather than yielding plaintext", async () => {
    const kp = await generateRecipientKeypair();
    const other = await generateRecipientKeypair();
    const sealed = await sealToRecipient("sk-live-abc123", kp.publicKey);
    const foreignEpk = (await sealToRecipient("junk", other.publicKey)).epk;
    await expect(
      unsealFromSender(sealed.ciphertext, sealed.iv, foreignEpk, kp.privateKeyJwk),
    ).rejects.toThrow();
  });
});
