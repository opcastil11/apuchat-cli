// Local store for the private half of a sealed secret request.
//
// Sealed mode (see secret-crypto.ts) works because the recipient's private key
// NEVER leaves the recipient's machine. That means it has to live somewhere
// between `apuchat request-secret` and `apuchat open` — two separate process
// invocations, possibly minutes apart. This file is that somewhere.
//
// It is deliberately NOT in the hub's data directory model: these keys belong
// to the person running the CLI, not to any channel or account, and no server
// code imports this module. Files are written mode 0600 in a 0700 directory,
// and pruned aggressively — a private key that outlives its request is pure
// liability with no upside.

import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** Requests older than this are swept on every access. Generous compared with
 *  the 15-minute default drop TTL, because the request is made BEFORE the
 *  sender acts and a human may be in the loop. */
const REQUEST_MAX_AGE_MS = 24 * 60 * 60 * 1000;

export type PendingRequest = {
  fingerprint: string;
  publicKey: string;
  privateKeyJwk: JsonWebKey;
  label?: string;
  createdAt: number;
};

function requestsDir(): string {
  const base = process.env.APUCHAT_HOME || join(homedir(), ".apuchat");
  const dir = join(base, "secret-requests");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  // Re-assert the mode even if the directory already existed — an inherited
  // world-readable dir would quietly undo the point of this file.
  try {
    chmodSync(dir, 0o700);
  } catch {
    /* best effort; Windows and some mounts don't support it */
  }
  return dir;
}

function pathFor(fingerprint: string): string {
  return join(requestsDir(), `${fingerprint}.json`);
}

/** Persist the private half. Returns the path so the CLI can tell the user
 *  where it is (and that it is theirs to delete). */
export function saveRequest(req: PendingRequest): string {
  pruneRequests();
  const path = pathFor(req.fingerprint);
  writeFileSync(path, JSON.stringify(req, null, 2), { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    /* best effort */
  }
  return path;
}

/** Look up by fingerprint. Returns null if absent or expired. */
export function loadRequest(fingerprint: string): PendingRequest | null {
  // Reject anything that isn't a plain fingerprint before touching the path —
  // this value arrives from a server response, so a '../' in it must not be
  // able to steer the read anywhere.
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(fingerprint)) return null;
  const path = pathFor(fingerprint);
  if (!existsSync(path)) return null;
  try {
    const req = JSON.parse(readFileSync(path, "utf8")) as PendingRequest;
    if (Date.now() - req.createdAt > REQUEST_MAX_AGE_MS) {
      rmSync(path, { force: true });
      return null;
    }
    return req;
  } catch {
    return null;
  }
}

/** Destroy a request's private key. Call this the moment a drop is unsealed —
 *  the key has done its one job and every second it survives is exposure. */
export function deleteRequest(fingerprint: string): void {
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(fingerprint)) return;
  rmSync(pathFor(fingerprint), { force: true });
}

/** List live requests, newest first. Used by `apuchat request-secret --list`. */
export function listRequests(): PendingRequest[] {
  pruneRequests();
  const dir = requestsDir();
  const out: PendingRequest[] = [];
  for (const name of readdirSync(dir)) {
    if (!name.endsWith(".json")) continue;
    try {
      out.push(JSON.parse(readFileSync(join(dir, name), "utf8")) as PendingRequest);
    } catch {
      /* skip unreadable/corrupt entries rather than failing the whole listing */
    }
  }
  return out.sort((a, b) => b.createdAt - a.createdAt);
}

/** Delete expired private keys. Called on every save/list. */
export function pruneRequests(now: number = Date.now()): number {
  const dir = requestsDir();
  let removed = 0;
  for (const name of readdirSync(dir)) {
    if (!name.endsWith(".json")) continue;
    const path = join(dir, name);
    try {
      const req = JSON.parse(readFileSync(path, "utf8")) as PendingRequest;
      if (now - req.createdAt > REQUEST_MAX_AGE_MS) {
        rmSync(path, { force: true });
        removed += 1;
      }
    } catch {
      // Unparseable file in a directory that should only hold our JSON —
      // remove it rather than leaving it to accumulate.
      rmSync(path, { force: true });
      removed += 1;
    }
  }
  return removed;
}
