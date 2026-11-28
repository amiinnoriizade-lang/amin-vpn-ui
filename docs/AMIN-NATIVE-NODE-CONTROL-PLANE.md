# AMIN Native Node Control Plane

Status: implementation branch opened; this document defines the release contract. It does not claim that native node management is production-ready.

## Required operator experience

1. An administrator creates a node in AMIN-UI and receives one short-lived bootstrap command.
2. The administrator runs that command once in the new Linux server's SSH session.
3. Bootstrap installs and enables the AMIN node connector, enrolls it with the panel, and establishes an authenticated outbound control channel.
4. All subsequent node, inbound, and client operations are performed in AMIN-UI. No Sanaei/3x-ui panel is installed or required on the node.

## Control-plane requirements

- Prefer an outbound mutually authenticated TLS stream from the node connector to the panel. Do not require a publicly exposed management port on the node.
- Enrollment credentials are single-use, short-lived, bound to the intended panel and node, stored hashed at rest where possible, and revocable.
- Runtime credentials are rotated independently from enrollment credentials. Never place reusable secrets in logs, URLs, or shell history beyond the one-time bootstrap token.
- The panel must distinguish the public VPN endpoint from the private management transport endpoint.
- Reconnects use bounded exponential backoff and report last-seen time, last error, connector version, Xray version, and capabilities.
- Revoking/deleting a node invalidates its credentials and closes its control stream.

## Xray mutation contract

- Adding/removing a client must use Xray HandlerService gRPC operations (AddUser / RemoveUser) and must not rewrite the Xray config or restart the Xray process.
- Adding/removing an inbound may require a controlled Xray config lifecycle until runtime inbound operations are proven compatible with the supported core. This must be explicit in the UI and tested separately.
- Runtime-created client credentials must be stored durably by the connector or panel so that share links remain available and can be reconciled after an Xray restart.
- The connector must reconcile desired state after Xray restarts and after temporary panel/transport outages. Reconciliation must be idempotent.
- A successful HTTP response alone is not proof of success. Verify the live Xray state and return a clear, actionable error if verification fails.

## Client lifecycle requirements

- Support VLESS, VMess, Trojan, and Shadowsocks with protocol-correct credentials and share URIs.
- Support enable/disable, expiry, traffic quota, and usage reporting only when enforcement is implemented end-to-end. Never show unsupported controls as if they were enforced.
- Quota and expiry enforcement must be durable across panel/connector restarts.
- Deleting a client removes it from the live Xray instance and desired-state storage.
- Routine client operations must not interrupt existing users' sessions.

## Node dashboard requirements

- Online means a successful authenticated connector heartbeat, not merely an open TCP port.
- Show control-channel latency separately from Xray health.
- Report live CPU, memory, uptime, network throughput, Xray state/version, inbound count, client count, and last synchronization error.
- Missing metrics are displayed as unavailable, never as fabricated zero values.

## Release gates

A release is blocked until all of these pass:

1. Agent unit tests, race tests, static checks, and cross-builds for supported architectures.
2. Integration test against a real Xray process with API enabled.
3. Add/remove clients for each supported protocol without changing the Xray PID.
4. Restart Xray and verify connector reconciliation restores managed clients.
5. Interrupt the control channel and verify safe reconnect and no duplicate clients.
6. Verify quota/expiry enforcement or hide those controls until implemented.
7. Verify bootstrap enrollment, replay rejection, token rotation, and revocation.
8. Verify the panel can add a clean node using only the one-time SSH bootstrap command.
9. Verify user-facing connection links use the public VPN address, never the management tunnel address.
10. Verify the existing panel database and production installation are not overwritten by development deployment.

## Known current gaps at branch creation

- The current standalone node-agent mutates the Xray JSON file and restarts the Xray service for client changes. This violates the no-interruption requirement.
- The current panel explicitly rejects quota/expiry for Agent nodes.
- The current agent enrollment/bootstrap lifecycle and outbound control channel are not implemented end-to-end.
- The current node UI still contains legacy Sanaei-compatible behavior for non-Agent nodes.
- The current agent client listing is based on the config file and is not yet a durable runtime desired-state model.

Do not bump the release version or advertise native node management as complete until the release gates above pass.
