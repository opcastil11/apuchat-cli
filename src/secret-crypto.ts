// Client-side crypto for secret drops. Runs in the CLI (`apuchat drop` /
// `apuchat open`) and, in mirrored form, in the hub's browser page.
//
// This file must NEVER be imported by server code. Its whole reason to exist is
// that the plaintext and the key stay on the client — if the hub imported it,
// someone would eventually be tempted to call encryptSecret() server-side and
// the guarantee would silently die.
//
// AES-256-GCM via WebCrypto. WebCrypto is global in Node >= 18 and in every
// browser, so this is zero-dependency and byte-identical on both sides — the
// browser page can open a drop the CLI created, and vice versa. GCM is
// authenticated, so a hub that tampered with the stored ciphertext would cause
// decryption to throw rather than yield an attacker-chosen credential.

const KEY_BYTES = 32; // AES-256
const IV_BYTES = 12; // 96-bit nonce, the GCM standard size

export type SealedSecret = {
  /** base64 — what the hub stores. */
  ciphertext: string;
  /** base64 — what the hub stores. */
  iv: string;
  /** base64url — the key. NEVER sent to the hub; it lives in the URL fragment. */
  key: string;
};

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

// The explicit `<ArrayBuffer>` matters: WebCrypto's BufferSource rejects a
// Uint8Array that might be backed by a SharedArrayBuffer, which is what
// Buffer.from() widens to.
function fromBase64(s: string): Uint8Array<ArrayBuffer> {
  const buf = Buffer.from(s, "base64");
  const out = new Uint8Array(new ArrayBuffer(buf.length));
  out.set(buf);
  return out;
}

function fromBase64Url(s: string): Uint8Array<ArrayBuffer> {
  const buf = Buffer.from(s, "base64url");
  const out = new Uint8Array(new ArrayBuffer(buf.length));
  out.set(buf);
  return out;
}

/** Encrypt with a fresh random key + nonce. Returns the two opaque halves plus
 *  the key the caller must put in the fragment (and nowhere else). */
export async function encryptSecret(plaintext: string): Promise<SealedSecret> {
  const rawKey = crypto.getRandomValues(new Uint8Array(KEY_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt"]);
  const buf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext),
  );
  return {
    ciphertext: toBase64(new Uint8Array(buf)),
    iv: toBase64(iv),
    // base64url so it survives being pasted into a URL fragment unescaped.
    key: Buffer.from(rawKey).toString("base64url"),
  };
}

// ── Sealed mode: ECDH P-256 + HKDF-SHA256 + AES-256-GCM ───────────────────────
//
// Link mode above has a sharp edge: the key is in the link, so if the link is
// relayed through an Apuchat channel the hub ends up holding both halves,
// because message text is stored in the clear. Sealed mode removes that edge —
// the AES key is
// DERIVED on both sides, never transmitted, so the entire exchange can go
// through the channel in the clear and the hub still cannot decrypt.
//
// P-256 rather than X25519: P-256 ECDH is supported by every browser and by
// Node 18+, while X25519 in WebCrypto is still uneven. The security margin is
// ample for a credential that lives for 15 minutes.

const CURVE = { name: "ECDH", namedCurve: "P-256" } as const;
/** Domain separation, so a derived key can't be confused with one from another
 *  protocol that happens to reuse the same ECDH output. */
const HKDF_INFO = new TextEncoder().encode("apuchat/secret-drop/v1");

export type RecipientKeypair = {
  /** base64url raw (uncompressed) public point — safe to publish anywhere. */
  publicKey: string;
  /** JWK of the private key. NEVER transmitted; stored locally, mode 600. */
  privateKeyJwk: JsonWebKey;
  /** Short stable id derived from the public key, so a sender can tell the
   *  receiver which of its pending requests a drop answers. Not a secret. */
  fingerprint: string;
};

/** Receiver side, step 1: mint a keypair. Only `publicKey` ever leaves. */
export async function generateRecipientKeypair(): Promise<RecipientKeypair> {
  const pair = await crypto.subtle.generateKey(CURVE, true, ["deriveBits"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const privateKeyJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  return {
    publicKey: Buffer.from(raw).toString("base64url"),
    privateKeyJwk,
    fingerprint: await fingerprintOf(raw),
  };
}

/** First 16 base64url chars of SHA-256(pubkey). Long enough to be unambiguous
 *  among a handful of pending requests; it is a lookup key, not a credential. */
export async function fingerprintOf(rawPublicKey: Uint8Array | string): Promise<string> {
  const bytes = typeof rawPublicKey === "string" ? fromBase64Url(rawPublicKey) : rawPublicKey;
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Buffer.from(new Uint8Array(digest)).toString("base64url").slice(0, 16);
}

async function deriveSharedKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  usage: "encrypt" | "decrypt",
): Promise<CryptoKey> {
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  // HKDF over the raw ECDH output — deriveBits gives the x-coordinate, which is
  // not uniformly random and must not be used as an AES key directly.
  const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: HKDF_INFO },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

export type SealedToRecipient = {
  ciphertext: string;
  iv: string;
  /** base64 of the sender's ephemeral public key — travels with the drop. */
  epk: string;
  /** fingerprint of the RECIPIENT's public key, so they know which key to use. */
  recipient: string;
};

/** Sender side: seal to the recipient's published public key. The sender's
 *  ephemeral private key is discarded immediately, so even the sender cannot
 *  decrypt this afterwards. */
export async function sealToRecipient(
  plaintext: string,
  recipientPublicKeyB64Url: string,
): Promise<SealedToRecipient> {
  const rawRecipient = fromBase64Url(recipientPublicKeyB64Url);
  const recipientKey = await crypto.subtle.importKey("raw", rawRecipient, CURVE, false, []);
  const ephemeral = await crypto.subtle.generateKey(CURVE, true, ["deriveBits"]);

  const aesKey = await deriveSharedKey(ephemeral.privateKey, recipientKey, "encrypt");
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const buf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    new TextEncoder().encode(plaintext),
  );
  const rawEpk = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));

  return {
    ciphertext: toBase64(new Uint8Array(buf)),
    iv: toBase64(iv),
    epk: toBase64(rawEpk),
    recipient: await fingerprintOf(rawRecipient),
  };
}

/** Recipient side: unseal with the private key that never left this machine. */
export async function unsealFromSender(
  ciphertext: string,
  iv: string,
  epkB64: string,
  privateKeyJwk: JsonWebKey,
): Promise<string> {
  const privateKey = await crypto.subtle.importKey("jwk", privateKeyJwk, CURVE, false, ["deriveBits"]);
  const senderKey = await crypto.subtle.importKey("raw", fromBase64(epkB64), CURVE, false, []);
  const aesKey = await deriveSharedKey(privateKey, senderKey, "decrypt");
  const buf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64(iv) }, aesKey, fromBase64(ciphertext));
  return new TextDecoder().decode(buf);
}

/** Decrypt a drop. Throws if the key is wrong or the ciphertext was tampered
 *  with — GCM authenticates, so there is no "partially right" outcome. */
export async function decryptSecret(
  ciphertext: string,
  iv: string,
  keyB64Url: string,
): Promise<string> {
  const rawKey = fromBase64Url(keyB64Url);
  if (rawKey.length !== KEY_BYTES) throw new Error("bad key length — is the #fragment complete?");
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
  const buf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(iv) },
    key,
    fromBase64(ciphertext),
  );
  return new TextDecoder().decode(buf);
}
