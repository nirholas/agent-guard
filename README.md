# agent-guard

**A local guard and egress proxy for always-on AI agents.** Your bot talks to `127.0.0.1`. The guard holds the real API keys, scans what comes back for prompt injection, blocks secrets from leaving, logs every call in a tamper-evident chain, and has a kill switch that works even when the bot is out of control.

[![CI: node --test](https://img.shields.io/badge/tests-17%20passing-brightgreen)](test/guard.test.js)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![dependencies: 0](https://img.shields.io/badge/dependencies-0-success)](package.json)
[![node >=20](https://img.shields.io/badge/node-%3E%3D20-informational)](package.json)

Docs site: **https://nirholas.github.io/agent-guard/** · Agent index: [llms.txt](llms.txt) · Agent rules: [AGENTS.md](AGENTS.md)

## Why

A personal agent that runs all day holds your API keys, reads untrusted web pages and messages, and can call tools. Three things go wrong again and again:

1. A page or message tells the agent to ignore its instructions and send your keys somewhere.
2. The agent, or a tool it runs, leaks a credential in a request body or a log.
3. Something misbehaves and there is no single switch that stops all of it, and no trustworthy record of what it did.

agent-guard sits between the agent and the network and answers all three. It works with any agent, framework or harness that can point an API base URL at a local address. It has no dependencies.

```
 your agent ──(client token)──▶ agent-guard ──(real key injected)──▶ api.provider.com
                                   │  ▲
                                   │  └── response scanned for prompt injection
                                   ├── request scanned for secrets
                                   ├── rate limit, host allow list, kill switch
                                   └── hash-chained audit log
```

## Install

```bash
npm install -g @nirholas/agent-guard
# or run from a clone
git clone https://github.com/nirholas/agent-guard && cd agent-guard && npm link
```

Requires Node 20 or newer.

## Quick start (two minutes)

```bash
export AGENT_GUARD_PASSPHRASE='a long passphrase you will not lose'
agent-guard init                      # writes agent-guard.json + an encrypted vault, prints a client token
```

Edit `agent-guard.json` to name the APIs your agent may reach:

```json
{
  "upstreams": {
    "anthropic": {
      "target": "https://api.anthropic.com",
      "inject": { "header": "x-api-key", "secret": "anthropic_key" },
      "rate_per_min": 120
    }
  }
}
```

Store the real key in the vault and start the guard:

```bash
agent-guard vault set anthropic_key        # paste the key on stdin, it is never echoed or logged
agent-guard start
```

Point the agent at the guard instead of the provider, using the client token from `init`:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787/u/anthropic
export ANTHROPIC_API_KEY=<client token>      # the bot only ever holds this
```

The SDK sends the client token; the guard strips it and injects the real key. If the agent is compromised, the attacker gets a token that only works against `127.0.0.1` and that you can rotate in one command.

## What it does

| Control | Behavior |
|---|---|
| Credential vault | Secrets encrypted at rest (AES-256-GCM, scrypt key). Injected on the way out. The agent never holds them. |
| Client tokens | Every request needs one. Compared in constant time. Rotate by changing a vault entry. |
| Injection scanner | Responses are scanned for instruction-override, fake system tags, hidden Unicode, exfiltration requests and markdown image beacons. Block or flag. Streams (SSE) are scanned with an overlap window. |
| Secret-leak blocker | Request bodies are scanned for known key shapes and for every value in your vault. A match is refused with a 403. |
| Host allow list | `CONNECT` tunnels only to listed hosts, and only with a client token. Everything else is refused and logged. |
| Rate limits | Per upstream, per minute. |
| Kill switch | `agent-guard kill` creates a file the guard checks on every request. It works with the guard process wedged, and from `POST /_guard/kill`. |
| Audit log | Append-only JSON lines. Each entry holds the hash of the one before it. `agent-guard audit verify` proves nothing was edited or removed. |
| Loopback only | The guard refuses to bind to a non-loopback address unless you opt in explicitly. |

## Commands

```
agent-guard init                       write config + vault with fresh tokens
agent-guard start [--config file]      run the guard
agent-guard vault set <name> [value]   store a secret (stdin when value omitted)
agent-guard vault list | remove <name>
agent-guard kill | resume              toggle the kill switch
agent-guard audit verify | tail        check or read the audit log
```

Admin API (bearer admin token): `GET /_guard/status`, `POST /_guard/kill`, `POST /_guard/resume`.

## Use it as a library

```js
import { createGuard, createAudit, openVault, validateConfig } from '@nirholas/agent-guard';

const vault = openVault('./guard.vault', process.env.AGENT_GUARD_PASSPHRASE);
vault.set('client_token', 'long-random-value');
vault.set('admin_token', 'another-long-random-value');
vault.set('api_key', process.env.REAL_KEY);

const config = validateConfig({
  upstreams: { api: { target: 'https://api.example.com', inject: { header: 'authorization', prefix: 'Bearer ', secret: 'api_key' } } },
});
const guard = createGuard({ config, vault, audit: createAudit(config.audit.file) });
console.log(await guard.listen()); // { address: '127.0.0.1', port: 8787, ... }
```

## Honest limits

agent-guard is a tripwire and a choke point, not a force field. Read [the threat model](docs/threat-model.md) before relying on it.

- Injection detection is pattern based. It catches the common, cheap attacks and the obvious ones in tool output. It will not catch a novel or well-disguised injection. Treat a block as a signal, and treat silence as no guarantee.
- It controls what goes through it. An agent that can make network calls some other way is not covered unless you also firewall it so the guard is the only route out.
- `CONNECT` tunnels are allow-listed and audited but not inspected, because that would require breaking TLS.
- The vault passphrase is read from the environment. Anyone who can read the guard's environment can unlock the vault.

## Documentation

- [Configuration reference](docs/configuration.md)
- [Integrations: SDKs, MCP servers, containers](docs/integrations.md)
- [Threat model](docs/threat-model.md)
- [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## Related

agent-guard comes out of work on [three.ws](https://three.ws), where agents hold wallets and every spend needs a previewed, hash-bound approval. The same rule applies here: what the human sees is what gets signed.

## License

MIT
