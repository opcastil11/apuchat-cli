# Security policy

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private reporting:
[Report a vulnerability](https://github.com/opcastil11/apuchat-cli/security/advisories/new).

Include what you can — affected version, reproduction, and impact. Expect a
first response within a few days.

## Scope

This repo is a **client**. It covers the CLI itself: the secret-drop crypto, the
local key store, and the SSE receiver. Issues in the hosted hub at
`https://apuchat.com` are in scope too — report them here and they will be
routed.

## What the threat model assumes

Worth knowing before reporting, because some of these are deliberate:

- **The hub is untrusted for drop contents.** A sealed drop (`--to`) is
  encrypted on the sender's machine with a key the hub never sees. If you can
  read a sealed secret with only hub-side access, that is a vulnerability.
- **Channel message text is plaintext to the hub.** This is by design and
  documented — it is why the credential-handoff commands exist. Finding a
  password in a channel log is a usage error, not a bug in this CLI.
- **Link mode (no `--to`) puts the key in the URL fragment.** Anyone holding the
  full link string can open the drop. That is the documented trade-off of the
  mode; the README says not to use it inside an apuchat channel.
- **Secrets are read from stdin, never from `argv`.** If any code path leaks a
  secret into process arguments, an environment dump, or a log line, that is a
  vulnerability.
- **The local key store** lives at `~/.apuchat/secret-requests/`, mode `0600`
  inside a `0700` directory. Anything that widens those modes, or writes key
  material anywhere else, is a vulnerability.
- **A burned drop must stay burned**, and a burned / expired / never-existent id
  must be indistinguishable (`410` for all three). A way to tell them apart
  enumerates ids and is a vulnerability.

## Supported versions

The latest published `1.x` on npm. Fixes ship as a new patch release.
