# AMIN Node Agent (bootstrap)

This is the first independently buildable agent milestone. It deliberately exposes only health, capabilities and basic runtime diagnostics; it does **not** yet modify Xray or customer accounts.

## Build

```sh
cd node-agent
go build -trimpath -ldflags="-s -w" -o amin-node-agent ./cmd/amin-node-agent
```

## Run

Generate a high-entropy token (at least 32 characters):

```sh
export AMIN_NODE_TOKEN="$(openssl rand -hex 32)"
export AMIN_NODE_LISTEN="127.0.0.1:8787"
./amin-node-agent
```

Health is public at `GET /health`. All `/api/v1/*` endpoints require `Authorization: Bearer $AMIN_NODE_TOKEN`.

```sh
curl -fsS http://127.0.0.1:8787/health
curl -fsS -H "Authorization: Bearer $AMIN_NODE_TOKEN" http://127.0.0.1:8787/api/v1/capabilities
curl -fsS -H "Authorization: Bearer $AMIN_NODE_TOKEN" http://127.0.0.1:8787/api/v1/system
```

The listener binds to loopback by default. Non-loopback binding is refused unless `AMIN_NODE_ALLOW_PUBLIC=yes`; public deployments must put the agent behind TLS and a network ACL. Never reuse the panel login password as the node token.

## Current scope

- Constant-time bearer-token check.
- Loopback-first binding and explicit public-bind opt-in.
- Bounded HTTP timeouts, method enforcement and no-store JSON responses.
- Health, capabilities and runtime diagnostics.
- No shell execution, no arbitrary path access, no Xray config writes.

## Next milestones

Implement enrollment/rotation, persistent secret handling, Xray config validation and atomic rollback, then inbound/client CRUD, URI/QR generation and traffic counters. Core integration must follow the contract in `docs/amin-native-node-api-v1.md`.
