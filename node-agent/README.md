# AMIN Node Agent

The standalone Go agent provides authenticated local control of an Xray node. Current Agent version: `0.3.0`. It binds to loopback by default and does not require Sanaei.

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

The agent needs read access to the Xray config. Inbound creation/deletion still validates and replaces the config and restarts Xray. Client creation/deletion is different: it uses the Xray HandlerService gRPC API and does not rewrite the Xray config or restart the service. The agent also writes a separate runtime-client state file with mode 0600. Set `AMIN_NODE_STATE` to move it; the default is `/var/lib/amin-node-agent/runtime-clients.json`. The service account needs permission to write that directory and connect to the local Xray API. Do not expose the HTTP API publicly without TLS and firewall restrictions.

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

Live client creation currently supports VLESS, VMess, Trojan, and Shadowsocks inbounds. VLESS/VMess require a syntactically valid UUID in `id`; Trojan/Shadowsocks require a non-empty `password`. New runtime-managed clients are persisted outside the Xray config and are merged into `GET /api/v1/inbounds` so the panel can retrieve their credentials. Deletion through this endpoint is intentionally limited to clients recorded in AMIN runtime state; legacy clients defined directly in the Xray config are not silently removed.

## Safety behavior

Inbound mutations still use staged config validation, timestamped backup, atomic replacement, and a service restart with rollback on failure. Runtime client mutations call Xray `HandlerService.AlterInbound` and do not touch the Xray config or restart Xray. Runtime client state is stored as JSON with restrictive file permissions. A full automatic re-application of saved runtime clients after an independent Xray restart is not yet implemented; do not treat that recovery scenario as complete.

The current implementation does not yet implement node enrollment/rotation, URI/QR generation, traffic accounting, or AMIN-UI Core integration. Runtime client persistence is in place, but automatic reconciliation after Xray process restart and end-to-end testing against a real Xray service remain release blockers. Do not treat this as a production-ready remote control plane yet.
