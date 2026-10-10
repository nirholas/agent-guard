# Integrations

The pattern is always the same: change the base URL to `http://127.0.0.1:8787/u/<upstream>` and give the client the guard's client token in place of the real key.

## Provider SDKs

```bash
# Anthropic SDKs and tools that read these variables
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787/u/anthropic
export ANTHROPIC_API_KEY=<client token>

# OpenAI-compatible SDKs
export OPENAI_BASE_URL=http://127.0.0.1:8787/u/openai/v1
export OPENAI_API_KEY=<client token>
```

Add the matching `upstreams` entries (`openai` with `authorization` and prefix `Bearer `, `anthropic` with `x-api-key`).

## Any HTTP tool

```bash
curl -H "x-guard-token: $TOKEN" http://127.0.0.1:8787/u/github/user
```

## HTTPS tunnels for tools that honor a proxy

```bash
export HTTPS_PROXY=http://guard:<client token>@127.0.0.1:8787
```

The guard tunnels only to `egress.allow_hosts`. Tunnels are audited by host, not inspected.

## MCP servers and tool servers

Run an MCP server that calls a web API with its base URL pointed at the guard. The server then holds a client token instead of the provider key, and tool output that carries an injection is blocked before the agent reads it.

## Containers and VMs

For a real boundary, run the agent where its only route out is the guard:

```bash
docker network create --internal agent-net
docker run --network agent-net -e ANTHROPIC_BASE_URL=http://guard:8787/u/anthropic my-agent
```

Run the guard on a second network with outbound access, bind it to the internal interface with `listen.allow_remote: true`, and keep that interface off the public internet. Without a network boundary an agent can simply bypass the proxy.

## Rotating a token

```bash
agent-guard vault set client_token "$(openssl rand -hex 24)"
```

Update the bot's environment. The old token stops working immediately.
