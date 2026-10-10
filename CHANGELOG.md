# Changelog

## 0.1.0 (2026-10-10)

First release.

- Reverse proxy with per-upstream credential injection from an encrypted vault
- Client tokens (also accepted in `x-api-key` and `Authorization: Bearer`)
- Prompt-injection scanner for responses, including streams
- Secret-leak scanner for request bodies, including vault values
- Allow-listed `CONNECT` tunnels
- Per-upstream rate limits
- File-based kill switch and admin API
- Hash-chained audit log with `audit verify`
- CLI: `init`, `start`, `vault`, `kill`, `resume`, `audit`
