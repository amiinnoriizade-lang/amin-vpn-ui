# AMIN Node Agent

The standalone Go agent provides authenticated local control of an Xray node. Current Agent version: `0.3.1`. It binds to loopback by default and does not require Sanaei.

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
- `PUT /api/v1/inbounds/{tag}/clients?email={email}`
- `DELETE /api/v1/inbounds/{tag}/clients?email={email}`

Create requests accept only `email`, `id`, `level`, `flow`, `alterId`, `security`, and `password`. VLESS/VMess require a syntactically valid UUID in `id`; Trojan and Shadowsocks require a non-empty `password`. Client identity credentials (`id` or `password`) and email must be unique within the inbound. String/numeric field types and whitespace in email are validated before any config write. Shadowsocks cipher selection belongs to the inbound's Xray settings, not an individual client.

Update requests use `PUT` with a JSON patch containing one or more of `id`, `password`, `level`, `flow`, `alterId`, or `security`. The email is supplied in the query string and cannot be changed by the patch. Unspecified client fields are preserved. The replacement credential is checked for protocol validity and duplicates before Xray config validation. Traffic quota, expiry enforcement, and enable/disable controls are not implemented by this Agent API.

### Per-user traffic statistics

- `GET /api/v1/stats` returns cumulative per-user upload/download counters and online-session state from Xray's StatsService.
- The Agent reads the existing Xray configuration and calls `xray api statsquery` plus `xray api statsonlineiplist`; it never resets counters and never modifies the Xray config to enable statistics.
- The API is advertised as `clients.stats` only when a valid loopback API inbound and `StatsService` are configured.
- If StatsService is not configured, node and client management continue to work, but live per-user speed remains unavailable and the panel records the reason.

To enable statistics, merge the equivalent settings into the existing Xray config (do not replace the complete config with this fragment). The API inbound must use the same tag as `api.tag`, listen only on loopback, and have a port available on the node:

```json
{
  "api": {
    "tag": "api",
    "services": ["StatsService"]
  },
  "stats": {},
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    }
  },
  "inbounds": [
    {
      "tag": "api",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }
    }
  ]
}
```

Ensure each managed client uses a policy level with user uplink/downlink statistics enabled. Validate the merged config with `xray run -test -config /path/to/config.json` and restart Xray using the operator's normal maintenance procedure. Never expose the Xray gRPC API on a public interface.

## Safety behavior

Before a mutation, the agent writes a staged JSON file and runs `xray run -test -config <staged-file>`. If validation succeeds, it creates a timestamped backup, atomically replaces the configured file, and restarts the configured systemd service. If restart fails, it restores the previous config and attempts to restart the service again. Backups are retained for operator-controlled cleanup.

The Agent supports authenticated inbound CRUD, client create/update/delete, and optional read-only per-user traffic counters. URI/QR generation is handled by AMIN-UI. Traffic quota and expiry enforcement, client enable/disable, node enrollment/rotation, and full production integration are still separate milestones; this Agent alone is not a complete production panel release.
