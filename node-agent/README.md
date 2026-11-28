# AMIN Node Agent

The standalone Go agent provides authenticated local control of an Xray node. Current Agent version: `0.2.2`. It binds to loopback by default and does not require Sanaei.

## Build and test

```sh
cd node-agent
go test -race ./...
go build -trimpath -ldflags="-s -w" -o amin-node-agent ./cmd/amin-node-agent
```

## Configure and run

The agent requires a high-entropy bearer token of at least 32 characters:

```sh
export AMIN_NODE_TOKEN="$(openssl rand -hex 32)"
export AMIN_NODE_LISTEN="127.0.0.1:8787"
export AMIN_XRAY_CONFIG="/usr/local/etc/xray/config.json"
export AMIN_XRAY_BINARY="/usr/local/bin/xray"
export AMIN_XRAY_SERVICE="xray"
./amin-node-agent
```

The process must have permission to read and replace the Xray config and restart the configured systemd service. Use a dedicated service account with narrowly scoped sudo/systemd permissions in production; do not run the API on a public interface without TLS termination and firewall restrictions.

- `GET /health` is public.
- All `/api/v1/*` endpoints require `Authorization: Bearer $AMIN_NODE_TOKEN`.
- `AMIN_NODE_LISTEN` defaults to `127.0.0.1:8787`.
- Non-loopback binding is refused unless `AMIN_NODE_ALLOW_PUBLIC=yes`.

## API v1

All responses use `{ "success": bool, "msg": string, "obj": any }`.

### Capabilities and system

- `GET /api/v1/capabilities`
- `GET /api/v1/system`

### Inbounds

- `GET /api/v1/inbounds`
- `POST /api/v1/inbounds`
- `DELETE /api/v1/inbounds/{tag}`

Example create request (the settings and stream settings are Xray-native objects):

```json
{
  "tag": "vless-reality-443",
  "port": 443,
  "listen": "0.0.0.0",
  "protocol": "vless",
  "settings": {
    "clients": [],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality"
  }
}
```

### Clients

- `POST /api/v1/inbounds/{tag}/clients`
- `DELETE /api/v1/inbounds/{tag}/clients?email={email}`

Client JSON accepts only `email`, `id`, `level`, `flow`, `alterId`, `security`, and `password`. VLESS/VMess require a syntactically valid UUID in `id`; Trojan and Shadowsocks require a non-empty `password`. Client identity credentials (`id` or `password`) and email must be unique within the inbound. String/numeric field types and whitespace in email are validated before any config write. Shadowsocks cipher selection belongs to the inbound's Xray settings, not an individual client.

## Safety behavior

Before a mutation, the agent writes a staged JSON file and runs `xray run -test -config <staged-file>`. If validation succeeds, it creates a timestamped backup, atomically replaces the configured file, and restarts the configured systemd service. If restart fails, it restores the previous config and attempts to restart the service again. Backups are retained for operator-controlled cleanup.

The current implementation manages inbound definitions and basic client records only. It does not yet implement node enrollment/rotation, URI/QR generation, traffic accounting, or AMIN-UI Core integration. Do not treat it as a production-ready remote control plane until those milestones and a full integration test are complete.
