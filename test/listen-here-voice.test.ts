// Voice notes reaching a parked agent through `listen-here`.
//
// An agent can't hear audio; it reads the line in its inbox. So a voice note has
// to arrive as text: the hub's transcript when it made one, otherwise a local
// one (--stt-cmd, or openai-whisper on PATH). Pinned here:
//
//   1. Uploaded attachments (url, no bytes) are fetched and saved like inline ones.
//   2. Audio with no hub transcript is transcribed by --stt-cmd, the audio path
//      going in $RR_AUDIO, and the text lands on the inbox line.
//   3. A hub transcript wins: the local engine is not run on top of it.
//   4. A url pointing anywhere but the hub is never fetched (any sender could
//      otherwise make this machine request what they like).

import { createServer, type Server } from "node:http";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { runListenHere } from "../src/listen-here.js";

const AUDIO = Buffer.from("OggS fake audio bytes");

type Stub = { server: Server; origin: string; hits: string[] };

async function stubHub(dm: (origin: string) => unknown): Promise<Stub> {
  const hits: string[] = [];
  let origin = "";
  const server = createServer((req, res) => {
    hits.push(`${req.method} ${req.url}`);
    if (req.url?.startsWith("/api/attachments/")) {
      res.writeHead(200, { "content-type": "audio/ogg" });
      res.end(AUDIO);
      return;
    }
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write(`event: message\ndata: ${JSON.stringify(dm(origin))}\n\n`);
  });
  origin = await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve(`http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`);
    });
  });
  return { server, origin, hits };
}

async function runFor(argv: string[], ms: number): Promise<number> {
  let code = -1;
  const done = runListenHere(argv).then((c) => (code = c));
  const timer = setTimeout(() => process.emit("SIGINT"), ms);
  await done;
  clearTimeout(timer);
  return code;
}

const voiceDm = (url: string, extra: Record<string, unknown> = {}) => ({
  id: 7,
  from: "human",
  to: "tester",
  text: "",
  at: 1,
  attachments: [{ id: "b1", mime: "audio/ogg", filename: "nota.ogg", size: AUDIO.length, url, ...extra }],
});

describe("listen-here voice notes", () => {
  let stub: Stub | null = null;
  let tmp = "";
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "apuchat-voice-"));
  });
  afterEach(async () => {
    if (stub) await new Promise((r) => stub!.server.close(() => r(null)));
    stub = null;
  });

  const argv = (inbox: string, ...more: string[]) => [
    "--dm", "--identity-key", "k", "--origin", stub!.origin,
    "--inbox", inbox, "--format", "text", "--quiet", ...more,
  ];
  const lines = (inbox: string) =>
    readFileSync(inbox, "utf8").split("\n").filter((l) => l && !l.startsWith("⟲"));

  it("downloads an uploaded voice note and transcribes it locally", async () => {
    stub = await stubHub((o) => voiceDm(`${o}/api/attachments/b1`));
    const inbox = join(tmp, "dm.log");
    // The command proves it got the saved file (wc -c of $RR_AUDIO).
    await runFor(argv(inbox, "--stt-cmd", 'printf "dijo hola, %s bytes" "$(wc -c < "$RR_AUDIO" | tr -d " ")"'), 2000);
    expect(stub.hits).toContain("GET /api/attachments/b1");
    const saved = join(tmp, "dm-attachments", "7-0-nota.ogg");
    expect(readFileSync(saved)).toEqual(AUDIO);
    expect(lines(inbox).join("\n")).toContain(`🎤 "dijo hola, ${AUDIO.length} bytes"`);
  });

  it("keeps the hub's transcript and does not run the local engine", async () => {
    stub = await stubHub((o) => voiceDm(`${o}/api/attachments/b1`, { transcript: "del hub" }));
    const inbox = join(tmp, "dm.log");
    const marker = join(tmp, "ran");
    await runFor(argv(inbox, "--stt-cmd", `touch ${marker}; echo local`), 2000);
    expect(lines(inbox).join("\n")).toContain('🎤 "del hub"');
    expect(existsSync(marker)).toBe(false);
  });

  it("never fetches an attachment url on another origin", async () => {
    stub = await stubHub(() => voiceDm("http://127.0.0.2:9/api/attachments/b1"));
    const inbox = join(tmp, "dm.log");
    await runFor(argv(inbox, "--no-stt"), 1500);
    expect(existsSync(join(tmp, "dm-attachments", "7-0-nota.ogg"))).toBe(false);
    expect(lines(inbox).join("\n")).toContain("📎 (1 not saved");
  });
});
