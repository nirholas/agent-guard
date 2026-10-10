# AGENTS.md

Instructions for AI coding agents working in this repository or setting it up for a user.

## What this is

`@nirholas/agent-guard`: a zero-dependency Node (>=20) loopback proxy that sits between an AI agent and its APIs. See `README.md`.

## Commands

- Test: `npm test` (built-in `node --test`, must stay green)
- Run: `node bin/agent-guard.js start`

## Rules

- No runtime dependencies. Use Node built-ins.
- Never log, echo, or return a secret. The audit log must not contain bodies, headers, or vault values (a test enforces it).
- Deny by default. Unknown upstream, host, token: refuse and audit.
- Bind to loopback unless `listen.allow_remote` is set.
- Every behavior change gets a test. Docs and `CHANGELOG.md` change with code.
- Scanner regexes must be bounded: they run on untrusted text.

## Setting it up for a user

1. Ask the user for a vault passphrase (`AGENT_GUARD_PASSPHRASE`). Never invent or store one for them.
2. `agent-guard init`, then list the APIs in `agent-guard.json`.
3. `agent-guard vault set <name>` with the secret on stdin. Do not put secrets in shell history or config files.
4. Point the agent's base URL at `http://127.0.0.1:8787/u/<upstream>` and give it the client token only.
5. Confirm with `GET /_guard/status` using the admin token, and `agent-guard audit verify`.
