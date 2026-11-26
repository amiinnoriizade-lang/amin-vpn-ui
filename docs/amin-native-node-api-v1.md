# AMIN Native Node API v1

Status: implementation branch; this document is the contract for the native node control plane.
Compatibility: existing Sanaei nodes remain supported during migration. Native nodes use the AMIN Node Agent and do not call the Sanaei API.

## Architecture

- AMIN-UI Core is the control plane: node registry, users/plans, desired state, credentials, audit trail and public management API.
- AMIN Node Agent runs on each managed server and owns the local Xray process/configuration.
- Core-to-agent traffic is authenticated with a per-node bearer token. Public endpoints must use HTTPS; plain HTTP is accepted only for an explicitly trusted private management tunnel (for example, a loopback SSH forward). The current Agent 0.2.1 integration stores the token in the existing node record and never serializes it to the browser. Hashed-at-rest enrollment, one-time display, rotation and revocation remain follow-up work.
- The agent binds to loopback by default; deployments expose it only through TLS/reverse proxy or a private management network.
- Agent requests have bounded body sizes and timeouts. Mutating operations are idempotent and audited by Core.

## Agent API

All responses use JSON: { "success": boolean, "msg": string, "obj": any }.
All routes except GET /health require Authorization: Bearer <node-token>.

- GET /health — agent version, uptime and Xray process status; no secrets.
- GET /api/v1/capabilities — supported Xray protocols and management features.
- GET /api/v1/inbounds — inbound inventory and sanitized client metadata.
- POST /api/v1/inbounds — create inbound.
- PUT /api/v1/inbounds/{id} — update inbound.
- DELETE /api/v1/inbounds/{id} — delete inbound.
- POST /api/v1/inbounds/{id}/clients — create client.
- PUT /api/v1/inbounds/{id}/clients/{clientId} — update client.
- DELETE /api/v1/inbounds/{id}/clients/{clientId} — delete client.
- GET /api/v1/clients/{clientId}/config — return share URI(s) and structured connection parameters.
- GET /api/v1/traffic — cumulative per-client counters and sample timestamp.
- GET /api/v1/system — CPU, memory, uptime, Xray version and agent version.

## Xray configuration safety

The agent must never accept arbitrary shell commands or arbitrary filesystem paths from Core. It validates protocol/client fields against an allowlist, writes a staged config atomically, runs the configured Xray binary in config-test mode, and only then activates it. Before activation it retains the last known-good config; on restart failure it rolls back. Every write is serialized with a process lock. Existing configs are backed up before first adoption.

## Native node identity and enrollment

1. Admin creates a pending native node in Core.
2. Core generates a cryptographically random one-time enrollment secret and displays it once.
3. Agent enrolls over HTTPS with the secret and node fingerprint; Core issues a unique long-lived node token.
4. Agent stores token in a root-readable file; Core stores only a hash.
5. Rotation/revocation is supported without changing customer credentials.

## Migration

Sanaei nodes remain a separate adapter. Existing node records are not silently converted. Admin can add a native node, migrate selected inbounds/clients, verify generated links and traffic, then disable the old node. No production node is modified by this branch.

## Initial implementation milestones

1. Define and test the API contract and secure agent transport.
2. Implement agent health/capabilities/system endpoints and enrollment.
3. Implement safe Xray config transaction layer.
4. Implement inbound/client CRUD and share-link generation.
5. Add Core-side native adapter, node type selector, inbound synchronization and VLESS/VMess/Trojan client create/delete.
6. Add Agent-side connection URI/QR generation, client updates, traffic counters, audit log and migration tooling.

## Security requirements

- TLS 1.2+; reject redirects; constant-time token comparison.
- Bind to 127.0.0.1 by default; explicit opt-in for public bind.
- Rate-limit authentication failures; redact Authorization headers and secrets from logs.
- Validate all identifiers and protocol-specific fields; no shell interpolation.
- Restrict CORS; no wildcard origins with credentials.
- Agent must not expose the Xray API or admin socket publicly.
