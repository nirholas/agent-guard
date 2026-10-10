# Configuration reference

`agent-guard.json` is plain JSON. Unknown keys are ignored. Every default is the safe choice.

| Key | Default | Meaning |
|---|---|---|
| `listen.host` | `127.0.0.1` | Bind address. Non-loopback values are refused unless `listen.allow_remote` is `true`. |
| `listen.port` | `8787` | Port. `0` picks a free one. |
| `upstreams.<name>.target` | required | Base URL of the API. Must be `https` unless it is loopback. |
| `upstreams.<name>.inject` | none | `{ "header", "secret", "prefix" }`. The vault secret named by `secret` is sent in `header`, with `prefix` in front. |
| `upstreams.<name>.rate_per_min` | unlimited | Requests per minute for this upstream. Over the limit returns 429. |
| `scan.mode` | `block` | `block` refuses a response that looks like an injection. `flag` passes it and adds an `x-guard-flags` header. |
| `scan.max_body_bytes` | `5000000` | Largest body the guard buffers and scans. Larger request bodies are refused (413). Larger responses pass unscanned and the audit entry says `scanned: false`. |
| `egress.allow_hosts` | `[]` | Hosts that `CONNECT` may tunnel to. `*.example.com` matches subdomains. |
| `egress.block_secrets` | `true` | Scan request bodies for key shapes and vault values. |
| `clients` | `["client_token"]` | Vault entries that count as valid client tokens. Add one per bot to revoke them independently. |
| `admin_secret` | `admin_token` | Vault entry used as the admin bearer token. |
| `vault.file` | `agent-guard.vault` | Encrypted vault path. |
| `audit.file` | `agent-guard-audit.jsonl` | Audit log path. |
| `kill_file` | `AGENT_GUARD_KILL` | While this file exists, every request is refused with 503. |

## Routes

- `ANY /u/<upstream>/<path>` forwards to `<target>/<path>`. Query strings pass through.
- `CONNECT host:port` tunnels to an allow-listed host. Present the client token in `Proxy-Authorization` (Bearer, or Basic with the token as the password).
- `GET /_guard/status`, `POST /_guard/kill`, `POST /_guard/resume` need `Authorization: Bearer <admin token>`.

## Responses the guard generates

| Status | `error` | Cause |
|---|---|---|
| 401 | `unauthorized` | Missing or wrong client or admin token |
| 403 | `secret_in_request` | A request body held a secret. `rules` lists which patterns matched. |
| 404 | `unknown_upstream` | The name is not in `upstreams` |
| 413 | `body_too_large` | Request body over `scan.max_body_bytes` |
| 429 | `rate_limited` | Over `rate_per_min` |
| 502 | `injection_suspected` | Response matched an injection rule in `block` mode |
| 502 | `upstream_unreachable` | The target could not be reached |
| 503 | `killed` | The kill switch is on |

## Audit log format

One JSON object per line: `ts`, `event`, event fields, `prev` (hash of the previous line), `hash` (sha256 of the line without `hash`). Events: `start`, `stop`, `request`, `response`, `deny`, `tunnel`, `kill`, `resume`, `stream_injection`, `upstream_error`. Request and response bodies, headers and secrets are never written.
