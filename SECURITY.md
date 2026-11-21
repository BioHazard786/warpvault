# Security policy

Warpvault exists to keep secrets away from the server, so security reports are welcome and taken seriously.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private reporting:
[Report a vulnerability](https://github.com/BioHazard786/warpvault/security/advisories/new).

Include what you found, how to reproduce it, and the impact you see. You'll get an answer within a few days.

## What is in scope

- The encryption format and its implementations (`protocol/PROTOCOL.md`, `web/src/lib/vault.ts`, `cli/internal/vault`).
- Anything that lets the server, a link preview, or another site learn a key, read a plaintext, burn a secret it shouldn't, or delete one without its delete token.
- The server API, rate limiting and the upload token.

The protocol's [threat model](protocol/PROTOCOL.md#7-threat-model) lists what is deliberately out of scope, for example that a server operator can serve modified JavaScript to the web app (use the CLI if you don't trust the host).

## Supported versions

Only the latest release is supported.
