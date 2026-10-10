# Security policy

agent-guard is a security tool, so reports are taken seriously.

## Reporting a vulnerability

Use GitHub private vulnerability reporting: https://github.com/nirholas/agent-guard/security/advisories/new

Please include the version, a minimal reproduction, and the impact you see. You will get an acknowledgement within 72 hours and a fix or a written assessment within 14 days. Please do not open a public issue for a vulnerability before a fix ships.

## Scope

In scope: authentication bypass of the client or admin token, a way to read vault contents or secrets from logs or responses, audit-log tampering that `audit verify` does not detect, request smuggling through the proxy, kill-switch bypass, and any path that makes the guard bind beyond loopback without opt-in.

Out of scope: injections that evade the pattern scanner (they are expected, see [the threat model](docs/threat-model.md)), and attacks that need the vault passphrase or local shell access to the guard's user.

New scanner rules and bypass examples are welcome as normal pull requests or issues.

## Supported versions

The latest minor release receives fixes.
