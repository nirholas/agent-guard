---
name: agent-guard-setup
description: Install, configure and operate agent-guard, a zero-dependency local proxy that keeps API keys in an encrypted vault, scans responses for prompt injection and requests for secret leaks, and logs every call to a hash-chained audit file. Use when hardening an always-on agent or bot.
---

# agent-guard

The agent talks to `127.0.0.1`. The guard holds the real keys, injects them on the way out, scans traffic, audits every call and has a kill switch. Node >= 20, no dependencies, MIT.

## Install

```bash
npm install -g @nirholas/agent-guard
```

## Setup

```bash
export AGENT_GUARD_PASSPHRASE='<long passphrase the user keeps>'   # unlocks the vault
agent-guard init          # writes agent-guard.json and the encrypted vault, prints a client token once
```

Edit `agent-guard.json` so `upstreams` names the APIs the agent may reach:

```json
{ "upstreams": { "anthropic": { "target": "https://api.anthropic.com", "inject": { "header": "x-api-key", "secret": "anthropic_key" }, "rate_per_min": 120 } } }
```

Store the real key (read from stdin when no value is given, so it never lands in shell history), then start:

```bash
agent-guard vault set anthropic_key
agent-guard start [--config file]
```

Point the agent at the guard and give it only the client token printed by `init`:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787/u/anthropic
export ANTHROPIC_API_KEY=<client token>
```

## Operate

```text
agent-guard vault list | remove <name>   names only, never values
agent-guard kill                          refuse every request (file based, works with the guard wedged)
agent-guard resume
agent-guard audit verify [--file f]       exit 0 if the hash chain is intact, 2 if broken
agent-guard audit tail [--file f]         last 20 entries
```

Admin API with the admin token as bearer: `GET /_guard/status`, `POST /_guard/kill`, `POST /_guard/resume`.

## Library use

```js
import { createGuard, createAudit, openVault, validateConfig } from '@nirholas/agent-guard';
```

Build a vault with `openVault(file, passphrase)`, a config with `validateConfig({ upstreams })`, then `createGuard({ config, vault, audit: createAudit(config.audit.file) })` and `await guard.listen()`.

## Rules for the assistant

- Never print, log or commit the passphrase, vault contents or tokens. Ask the user to run `vault set` themselves or pipe the value in without echoing it.
- State the limits: injection detection is pattern based, `CONNECT` tunnels are allow-listed but not inspected, and an agent with another network route is not covered unless firewalled so the guard is the only way out. See `docs/threat-model.md`.
