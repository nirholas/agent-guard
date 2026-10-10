# Threat model

## What it defends against

| Threat | Control |
|---|---|
| Untrusted content tells the agent to disobey or exfiltrate | Responses scanned for override phrases, fake system tags, hidden Unicode, exfiltration requests, markdown image beacons |
| The agent or a tool leaks a credential in an outbound request | Request bodies scanned for key shapes and for every vault value |
| A compromised agent steals the provider key | The agent never holds it. It holds a rotatable client token valid only for the loopback guard |
| The agent reaches hosts it should not | Reverse proxy reaches only named upstreams. `CONNECT` reaches only allow-listed hosts |
| Runaway spending or request loops | Per-upstream rate limit, kill switch |
| Disputed or edited history | Hash-chained audit log, `audit verify` |

## What it does not defend against

- **Novel injections.** Scanning is pattern based. A paraphrase the rules do not know passes. Layer other controls: least-privilege tools, human approval for anything irreversible.
- **Bypass.** If the agent can open its own sockets, it can skip the guard. Enforce the boundary with a network policy, an internal Docker network, or a firewall rule.
- **Inspection of tunneled HTTPS.** Tunnels are metadata only.
- **A hostile local user.** The vault passphrase lives in the guard's environment; the client token lives in the bot's. Same-machine attackers with those rights win.
- **Logic errors in what the agent is allowed to do.** The guard cannot tell a good API call from a bad one that is well formed.

## Design rules

1. Deny by default: unknown upstream, host, or token is refused and logged.
2. No secret ever reaches a log, an error body, or a header returned to the agent.
3. The kill switch must work when the process cannot be trusted to respond, so it is a file.
4. Bind to loopback. Remote binds are an explicit opt-in.
5. Zero runtime dependencies, so there is no supply chain to audit beyond Node itself.

Report weaknesses through [SECURITY.md](../SECURITY.md).
