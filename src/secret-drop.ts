// `apuchat drop` / `apuchat open` — the agent-facing half of secret drops.
//
// These two subcommands are where the encryption actually happens. The hub
// deliberately cannot do it: if the plaintext reached apuchat.com the whole
// point would be gone. So the sender's own machine encrypts, uploads opaque
// bytes, and prints a link whose #fragment carries the key. The receiver's own
// machine fetches the bytes and decrypts locally.
//
// WHY A CLI AND NOT AN MCP TOOL. An MCP tool call travels to the hub. A tool
// that took `secret: "sk-live-..."` would put the credential in the hub's
// process memory and quite possibly its request logs — exactly the thing the
// agent was right to refuse. Running the crypto in the agent's own shell is the
// only shape that keeps the guarantee honest. This is also the one real
// limitation to be upfront about: an agent with NO shell (remote MCP only)
// cannot produce a true end-to-end drop. It can still *receive* one by opening
// the link in a browser.
//
// The secret is read from stdin, never from argv — argv is visible in `ps` to
// every user on the box and is routinely captured in shell history.

import { parseArgs } from "node:util";
import {
  decryptSecret,
  encryptSecret,
  generateRecipientKeypair,
  sealToRecipient,
  unsealFromSender,
} from "./secret-crypto.js";
import { deleteRequest, listRequests, loadRequest, saveRequest } from "./secret-requests.js";

const DEFAULT_ORIGIN = "https://apuchat.com";

/** Prefix that makes a request code recognisable when it is pasted into a chat
 *  message alongside prose. */
const REQUEST_PREFIX = "apuchat-req:";

const DROP_HELP = `apuchat drop — encrypt a secret locally, upload only ciphertext, hand over a link

usage:
  printf %s "$MY_SECRET" | apuchat drop --to <request-code>   # SEALED (recommended)
  printf %s "$MY_SECRET" | apuchat drop                       # LINK mode
  apuchat drop --file .env.production [options]

TWO MODES — pick by where the link will travel:

  SEALED (--to <request-code>)  ← use this when relaying through an Apuchat channel
    The receiver first runs \`apuchat request-secret\` and sends you its request
    code. You encrypt to that public key, so the decryption key is DERIVED on
    both ends and never transmitted at all. The resulting link carries nothing
    secret — you can paste it, and the request code, straight into a channel and
    the hub still cannot decrypt. This is the only mode that holds up if the hub
    itself is compromised.

  LINK (no --to)
    A random key is generated here and travels in the link's #fragment.
    Fragments are never sent to a server, so *visiting* the link doesn't leak
    the key. BUT if you paste the link into an Apuchat channel, the fragment
    becomes message text — and message text is stored in plaintext, so the hub
    would hold both halves. Use link mode only when the link travels OUTSIDE
    Apuchat: Signal, a password manager, read aloud, another tool.

input (pick one):
  (stdin)             the secret, read from stdin — preferred
  --file <path>       read the secret from a file instead

options:
  --to <code>         recipient's request code from \`apuchat request-secret\`
                      (enables sealed mode)
  --label <text>      short NON-SECRET description shown to the receiver
                      (e.g. "staging DB password"). Never put the secret here.
  --ttl <seconds>     lifetime before it self-destructs (default: 900, max: 86400)
  --reads <n>         how many times it may be opened (default: 1, max: 5)
  --origin <url>      hub origin (default: ${DEFAULT_ORIGIN})
  --json              print JSON instead of human text
  --help, -h          show this help

NEVER pass the secret as a flag — argv is world-readable via \`ps\`.
`;

const REQUEST_HELP = `apuchat request-secret — ask a peer for a credential, sealed to a key only you hold

usage:
  apuchat request-secret [--label "prod DB password"]
  apuchat request-secret --list

Generates an ECDH keypair on THIS machine. The private half is written to
~/.apuchat/secret-requests/ (mode 600) and never leaves; only the public half
goes in the request code you send to the peer.

Because the sender derives the encryption key from your public key rather than
inventing one and shipping it, NOTHING secret ever crosses the hub — you can
send the request code and the resulting link through an Apuchat channel in the
clear and the hub still cannot read the secret.

The peer answers with:
  printf %s "$SECRET" | apuchat drop --to <your-request-code>

then sends you the link, which you open with \`apuchat open <link>\`.

options:
  --label <text>      NON-SECRET note about what you're asking for
  --list              show your pending requests
  --json              print JSON instead of human text
  --help, -h          show this help
`;

const OPEN_HELP = `apuchat open — fetch a one-time secret drop and decrypt it locally

usage:
  apuchat open '<link>'
  apuchat open --id <id> --key <key> [--origin <url>]

Pass the FULL link including the #fragment, in single quotes so the shell does
not strip it. Opening BURNS the drop: the hub deletes the ciphertext, and a
second attempt returns 410. The decrypted secret is printed to stdout and
nowhere else — pipe it straight into whatever needs it rather than letting it
land in a file or in your scrollback.

options:
  --id <id>           drop id, if you are not passing a full link
  --key <key>         the fragment key, if you are not passing a full link
  --origin <url>      hub origin (default: ${DEFAULT_ORIGIN})
  --json              print JSON instead of the bare secret
  --help, -h          show this help
`;

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return "";
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

/** `apuchat request-secret` — the receiver mints a keypair and publishes only
 *  the public half. This is what makes sealed mode possible. */
export async function runRequestSecret(argv: string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        label: { type: "string" },
        list: { type: "boolean" },
        json: { type: "boolean" },
        help: { type: "boolean", short: "h" },
      },
      strict: true,
      allowPositionals: false,
    });
  } catch (e) {
    console.error((e as Error).message);
    console.error("\n" + REQUEST_HELP);
    return 2;
  }
  if (parsed.values.help) {
    console.log(REQUEST_HELP);
    return 0;
  }

  if (parsed.values.list) {
    const pending = listRequests();
    if (parsed.values.json) {
      // Never print the private key, not even here.
      console.log(
        JSON.stringify(
          pending.map((r) => ({
            fingerprint: r.fingerprint,
            label: r.label ?? null,
            created_at: r.createdAt,
            request_code: REQUEST_PREFIX + r.publicKey,
          })),
          null,
          2,
        ),
      );
      return 0;
    }
    if (pending.length === 0) {
      console.log("no pending secret requests.");
      return 0;
    }
    for (const r of pending) {
      console.log(
        `${r.fingerprint}  ${new Date(r.createdAt).toISOString()}  ${r.label ?? "(no label)"}\n  ${REQUEST_PREFIX}${r.publicKey}`,
      );
    }
    return 0;
  }

  const label = parsed.values.label;
  const pair = await generateRecipientKeypair();
  const path = saveRequest({
    fingerprint: pair.fingerprint,
    publicKey: pair.publicKey,
    privateKeyJwk: pair.privateKeyJwk,
    label,
    createdAt: Date.now(),
  });
  const code = REQUEST_PREFIX + pair.publicKey;

  if (parsed.values.json) {
    console.log(
      JSON.stringify({ request_code: code, fingerprint: pair.fingerprint, label: label ?? null }, null, 2),
    );
    return 0;
  }

  console.log(
    [
      code,
      "",
      `Send that line to whoever has the secret${label ? ` (asking for: ${label})` : ""}.`,
      "It is safe to paste into a channel — it is a PUBLIC key. Nothing derived",
      "from it lets the hub, or anyone else, read what comes back.",
      "",
      "They reply by running:",
      `  printf %s "$SECRET" | npx -y apuchat drop --to ${code}`,
      "",
      "…and sending you the link it prints. Open it with:",
      "  apuchat open '<link>'",
      "",
      `Your private key: ${path} (mode 600, deleted automatically once you open the drop).`,
    ].join("\n"),
  );
  return 0;
}

/** `apuchat drop` — encrypt locally, upload ciphertext, print the link. */
export async function runDrop(argv: string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        file: { type: "string" },
        to: { type: "string" },
        label: { type: "string" },
        ttl: { type: "string" },
        reads: { type: "string" },
        origin: { type: "string" },
        json: { type: "boolean" },
        help: { type: "boolean", short: "h" },
        // Intentionally absent: --secret. See the header note about argv.
      },
      strict: true,
      allowPositionals: false,
    });
  } catch (e) {
    console.error((e as Error).message);
    console.error("\n" + DROP_HELP);
    return 2;
  }
  if (parsed.values.help) {
    console.log(DROP_HELP);
    return 0;
  }

  const { file, label, origin: originFlag, json } = parsed.values;

  let plaintext: string;
  if (file) {
    const { readFileSync } = await import("node:fs");
    try {
      plaintext = readFileSync(file, "utf8");
    } catch (e) {
      console.error(`cannot read ${file}: ${(e as Error).message}`);
      return 1;
    }
  } else {
    plaintext = await readStdin();
    if (!plaintext) {
      console.error(
        "no secret on stdin.\n\n" +
          "  printf %s \"$MY_SECRET\" | apuchat drop --label 'staging key'\n\n" +
          "(use printf, not echo, so no trailing newline is baked into the secret)",
      );
      return 2;
    }
  }
  if (!plaintext.trim()) {
    console.error("refusing to drop an empty secret");
    return 2;
  }

  const origin = (originFlag || DEFAULT_ORIGIN).replace(/\/+$/, "");
  const ttlSeconds = parsed.values.ttl ? Number(parsed.values.ttl) : undefined;
  const maxReads = parsed.values.reads ? Number(parsed.values.reads) : undefined;
  if (ttlSeconds !== undefined && (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0)) {
    console.error("--ttl must be a positive number of seconds");
    return 2;
  }
  if (maxReads !== undefined && (!Number.isFinite(maxReads) || maxReads < 1)) {
    console.error("--reads must be >= 1");
    return 2;
  }

  // THE ENCRYPTION HAPPENS HERE, before any network call. In link mode the
  // `key` must never be put in the request body below; in sealed mode there is
  // no key to leak — it is derived on both ends.
  const to = parsed.values.to;
  let payload: Record<string, unknown>;
  let fragmentKey: string | null = null;

  if (to) {
    const recipientPub = to.startsWith(REQUEST_PREFIX) ? to.slice(REQUEST_PREFIX.length) : to;
    if (!/^[A-Za-z0-9_-]+$/.test(recipientPub)) {
      console.error(
        `--to does not look like a request code. Expected something like:\n  ${REQUEST_PREFIX}BEl2…\n` +
          "Ask the receiver to run `apuchat request-secret` and send you the line it prints.",
      );
      return 2;
    }
    let s;
    try {
      s = await sealToRecipient(plaintext, recipientPub);
    } catch (e) {
      console.error(`could not seal to that request code: ${(e as Error).message}`);
      return 2;
    }
    payload = { ciphertext: s.ciphertext, iv: s.iv, epk: s.epk, recipient: s.recipient };
  } else {
    const s = await encryptSecret(plaintext);
    fragmentKey = s.key;
    payload = { ciphertext: s.ciphertext, iv: s.iv };
  }

  let res: Response;
  try {
    res = await fetch(`${origin}/api/secrets`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...payload, label, ttl_seconds: ttlSeconds, max_reads: maxReads }),
    });
  } catch (e) {
    console.error(`cannot reach ${origin}: ${(e as Error).message}`);
    return 1;
  }

  const body = (await res.json().catch(() => ({}))) as { id?: string; expires_at?: number; error?: string };
  if (!res.ok || !body.id) {
    console.error(`drop failed (${res.status}): ${body.error ?? "unknown error"}`);
    return 1;
  }

  // Sealed mode links carry nothing secret, so no fragment at all.
  const link = fragmentKey ? `${origin}/s/${body.id}#${fragmentKey}` : `${origin}/s/${body.id}`;
  const expires = body.expires_at ? new Date(body.expires_at).toISOString() : "?";

  if (json) {
    console.log(
      JSON.stringify(
        {
          link,
          id: body.id,
          mode: fragmentKey ? "link" : "sealed",
          expires_at: body.expires_at,
          reads: maxReads ?? 1,
        },
        null,
        2,
      ),
    );
    return 0;
  }

  const trailer = fragmentKey
    ? [
        "⚠ LINK MODE: the key is the part after '#'. Everything after '#' is a URL",
        "fragment, so *visiting* this link never sends the key to a server — but if",
        "you paste this link into an Apuchat channel, the key becomes message text,",
        "and message text is stored in plaintext. The hub would then hold both",
        "halves. Relay this link OUTSIDE Apuchat (Signal, password manager, aloud).",
        "",
        "To relay through an Apuchat channel instead, ask the receiver to run",
        "`apuchat request-secret` and re-drop with `--to <their code>` — that mode",
        "transmits no key at all.",
        "",
        "The receiver runs:  apuchat open '<link>'   (quotes matter — they keep the #)",
      ]
    : [
        "✓ SEALED MODE: this link carries nothing secret. The decryption key was",
        "derived from the recipient's public key and never transmitted, so you can",
        "paste this straight into a channel — the hub cannot decrypt it even with",
        "the full message history.",
        "",
        "Only the holder of the matching private key can open it:  apuchat open <link>",
      ];

  console.log(
    [link, "", `expires: ${expires}   opens: ${maxReads ?? 1}   label: ${label ?? "(none)"}`, "", ...trailer].join(
      "\n",
    ),
  );
  return 0;
}

/** `apuchat open` — fetch, burn, decrypt locally. */
export async function runOpen(argv: string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        id: { type: "string" },
        key: { type: "string" },
        origin: { type: "string" },
        json: { type: "boolean" },
        help: { type: "boolean", short: "h" },
      },
      strict: true,
      allowPositionals: true,
    });
  } catch (e) {
    console.error((e as Error).message);
    console.error("\n" + OPEN_HELP);
    return 2;
  }
  if (parsed.values.help) {
    console.log(OPEN_HELP);
    return 0;
  }

  let origin = (parsed.values.origin || DEFAULT_ORIGIN).replace(/\/+$/, "");
  let id = parsed.values.id;
  let key = parsed.values.key;

  const positional = parsed.positionals[0];
  if (positional) {
    let url: URL;
    try {
      url = new URL(positional);
    } catch {
      console.error(`not a valid link: ${positional}`);
      return 2;
    }
    const m = /\/s\/([^/?#]+)/.exec(url.pathname);
    if (!m) {
      console.error(`cannot find a drop id in ${url.pathname} (expected /s/<id>)`);
      return 2;
    }
    id = m[1];
    // A missing fragment is NOT an error any more: sealed-mode links have none,
    // because sealed mode transmits no key. We only know which case we are in
    // after the server tells us whether the drop is sealed, so defer the
    // "your shell ate the #" advice until then.
    key = url.hash && url.hash !== "#" ? decodeURIComponent(url.hash.slice(1)) : undefined;
    origin = url.origin;
  }

  if (!id) {
    console.error("need a full link, or --id.\n\n" + OPEN_HELP);
    return 2;
  }

  // PEEK FIRST (GET does not burn). Burning and *then* discovering we cannot
  // decrypt destroys the credential for everyone, including the legitimate
  // recipient who simply ran this from the wrong shell. Both foreseeable
  // failures — a sealed drop whose private key isn't on this machine, and a
  // link-mode drop whose '#key' the shell ate — are detectable here, before
  // anything irreversible happens.
  let peek: { sealed?: boolean; recipient?: string; error?: string };
  try {
    const pres = await fetch(`${origin}/api/secrets/${encodeURIComponent(id)}`);
    peek = (await pres.json().catch(() => ({}))) as typeof peek;
    if (pres.status === 410) {
      console.error(
        "this drop is gone — already opened, expired, or never existed.\n" +
          "Ask the sender for a new one; drops are single-use by design.",
      );
      return 1;
    }
  } catch (e) {
    console.error(`cannot reach ${origin}: ${(e as Error).message}`);
    return 1;
  }

  // Sealed: do we actually hold the private key? Checked before the burn.
  let sealedRequest: ReturnType<typeof loadRequest> = null;
  if (peek.sealed) {
    sealedRequest = loadRequest(peek.recipient ?? "");
    if (!sealedRequest) {
      console.error(
        `this drop is sealed to a key this machine doesn't have (recipient ${peek.recipient || "unknown"}).\n` +
          "It can only be opened where `apuchat request-secret` was run. If that was\n" +
          "here, the request may have expired (24h) or been cleaned up.\n" +
          "The drop has NOT been consumed — it is still waiting on the right machine.",
      );
      return 1;
    }
  } else if (!key) {
    console.error(
      "this drop needs a key from the link's #fragment, and the link you passed\n" +
        "has none. Your shell probably ate it — '#' starts a comment unless the\n" +
        "link is quoted. Retry with single quotes:\n\n" +
        "  apuchat open '<the whole link, including everything after #>'\n\n" +
        "The drop has NOT been consumed — the whole link will still work.",
    );
    return 2;
  }

  let res: Response;
  try {
    // This is the burn. Everything we could check without it has been checked.
    res = await fetch(`${origin}/api/secrets/${encodeURIComponent(id)}`, { method: "POST" });
  } catch (e) {
    console.error(`cannot reach ${origin}: ${(e as Error).message}`);
    return 1;
  }

  const body = (await res.json().catch(() => ({}))) as {
    ciphertext?: string;
    iv?: string;
    label?: string;
    epk?: string;
    recipient?: string;
    error?: string;
  };
  if (res.status === 410) {
    console.error(
      "this drop is gone — already opened, expired, or never existed.\n" +
        "Ask the sender for a new one; drops are single-use by design.",
    );
    return 1;
  }
  if (!res.ok || !body.ciphertext || !body.iv) {
    console.error(`open failed (${res.status}): ${body.error ?? "unknown error"}`);
    return 1;
  }

  let plaintext: string;
  if (body.epk) {
    // SEALED MODE. Decrypt with the private key we generated locally in
    // `request-secret` — it never left this machine, so the hub could not have
    // decrypted this even holding the entire channel history.
    // The peek above already proved we hold it; re-load only if the drop turned
    // out to be sealed to a different key than the peek reported.
    const fingerprint = body.recipient ?? "";
    const req = sealedRequest?.fingerprint === fingerprint ? sealedRequest : loadRequest(fingerprint);
    if (!req) {
      console.error(
        `this drop is sealed to a key this machine doesn't have (recipient ${fingerprint || "unknown"}).\n` +
          "It can only be opened where `apuchat request-secret` was run. If that was\n" +
          "here, the request may have expired (24h) or been cleaned up.\n" +
          "NOTE: the drop has already been consumed — ask the sender for a new one.",
      );
      return 1;
    }
    try {
      plaintext = await unsealFromSender(body.ciphertext, body.iv, body.epk, req.privateKeyJwk);
    } catch {
      console.error(
        "could not unseal the drop — the ciphertext does not match this private key.\n" +
          "NOTE: the drop has already been consumed; ask the sender to send a new one.",
      );
      return 1;
    }
    // The private key has done its single job. Every second it survives past
    // this point is exposure with no remaining benefit.
    deleteRequest(fingerprint);
  } else {
    if (!key) {
      console.error(
        "this drop needs a key from the link's #fragment, and the link you passed\n" +
          "has none. Your shell probably ate it — '#' starts a comment unless the\n" +
          "link is quoted. Retry with single quotes:\n\n" +
          "  apuchat open '<the whole link, including everything after #>'\n\n" +
          "NOTE: the drop has already been consumed by this attempt; ask the sender\n" +
          "for a new one.",
      );
      return 2;
    }
    try {
      plaintext = await decryptSecret(body.ciphertext, body.iv, key);
    } catch {
      console.error(
        "decryption failed. The ciphertext came through, so the key is wrong or\n" +
          "truncated — check you copied the whole link including everything after #.\n" +
          "NOTE: the drop has already been consumed; ask the sender to send a new one.",
      );
      return 1;
    }
  }

  if (parsed.values.json) {
    console.log(JSON.stringify({ secret: plaintext, label: body.label ?? null }, null, 2));
  } else {
    // Bare secret on stdout, nothing else, so it can be piped safely.
    process.stdout.write(plaintext);
    if (!plaintext.endsWith("\n")) process.stdout.write("\n");
  }
  return 0;
}
