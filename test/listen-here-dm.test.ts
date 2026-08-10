// `apuchat listen-here --dm` — parking on your own @handle's inbox.
//
// This repo is a CLIENT; there is no hub to boot in CI. So the tests run against
// a throwaway http server that speaks just enough of GET /api/dm/stream, which
// is enough to pin the three rules that are easy to break in a refactor:
//
//   1. DM mode needs no channel/token/session — the identity IS the address.
//   2. A 4xx exits 1 instead of reconnecting. In channel mode a 4xx usually means
//      a lost session and re-joining is right; here there is nothing to re-join
//      with (the key was rejected), and a retry loop on a dead key spins forever.
//   3. Delivered DMs land in --inbox, and the hook env says RR_MODE=dm so a
//      wake-up handler knows to answer with a DM, not a channel send.

import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { runListenHere } from "../src/listen-here.js";

type Stub = { server: Server; origin: string; hits: string[] };

/** A hub stub: `status` 200 streams one DM then holds the connection open,
 *  anything else answers that status and closes. */
async function stubHub(status: number, dm?: unknown): Promise<Stub> {
  const hits: string[] = [];
  const server = createServer((req, res) => {
    hits.push(`${req.method} ${req.url}`);
    if (status !== 200) {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "nope" }));
      return;
    }
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
    res.write(`event: hello\ndata: ${JSON.stringify({ callsign: "tester" })}\n\n`);
    if (dm) res.write(`event: message\ndata: ${JSON.stringify(dm)}\nid: 1\n\n`);
    // deliberately left open — the receiver is supposed to hold it
  });
  const origin: string = await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolve(`http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`);
    });
  });
  return { server, origin, hits };
}

/** Run the receiver, then SIGINT it — it is a daemon, so it never returns on its own. */
async function runFor(argv: string[], ms: number): Promise<number> {
  let code = -1;
  const done = runListenHere(argv).then((c) => (code = c));
  const timer = setTimeout(() => process.emit("SIGINT"), ms);
  await done;
  clearTimeout(timer);
  return code;
}

describe("apuchat listen-here --dm", () => {
  let stub: Stub | null = null;
  let tmp = "";

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "apuchat-dm-"));
  });
  afterEach(async () => {
    if (stub) await new Promise((r) => stub!.server.close(() => r(null)));
    stub = null;
  });

  it("refuses --dm without an identity key", async () => {
    expect(await runFor(["--dm", "--quiet"], 1000)).toBe(2);
  });

  it("refuses --dm together with --session (that flag is channel mode)", async () => {
    expect(await runFor(["--dm", "--identity-key", "k", "--session", "s", "--quiet"], 1000)).toBe(2);
  });

  it("streams the inbox — no channel, no token, no session", async () => {
    // The hub's DirectMessage shape: {id, from, to, text, at}.
    stub = await stubHub(200, {
      id: 1,
      from: "caller",
      to: "tester",
      text: "https://meet.apuchat.com/call#c=abc&t=xyz",
      at: 1,
    });
    const inbox = join(tmp, "dm.log");
    await runFor(
      ["--dm", "--identity-key", "k", "--origin", stub.origin, "--inbox", inbox, "--format", "text", "--quiet"],
      1500,
    );
    expect(stub.hits.some((h) => h.startsWith("GET /api/dm/stream"))).toBe(true);
    const lines = readFileSync(inbox, "utf8")
      .trim()
      .split("\n")
      .filter((l) => !l.startsWith("⟲"));
    expect(lines.join("\n")).toContain("meet.apuchat.com/call#c=abc&t=xyz");
  });

  it("exits 1 on a rejected identity key instead of reconnecting forever", async () => {
    stub = await stubHub(401);
    const code = await runFor(["--dm", "--identity-key", "revoked", "--origin", stub.origin, "--quiet"], 4000);
    expect(code).toBe(1);
    // One attempt, not a retry storm.
    expect(stub.hits.length).toBe(1);
  });
});
