#!/usr/bin/env bash
set -Eeuo pipefail

# Run on the AMIN node host as root. This creates and deletes one disposable
# Xray client through the live Agent API, then verifies the Xray PID did not change.
AGENT_ENV="${AMIN_AGENT_ENV_FILE:-/opt/amin-node-agent/agent.env}"
if [[ ! -r "$AGENT_ENV" ]]; then
  echo "ERROR: cannot read Agent environment file: $AGENT_ENV" >&2
  exit 2
fi

# agent.env is a root-owned shell environment file installed by the Agent setup.
set -a
# shellcheck disable=SC1090
. "$AGENT_ENV"
set +a

: "${AMIN_NODE_TOKEN:?AMIN_NODE_TOKEN is missing from $AGENT_ENV}"
LISTEN="${AMIN_NODE_LISTEN:-127.0.0.1:8787}"
HOST="${LISTEN%:*}"
PORT="${LISTEN##*:}"
if [[ "$HOST" == "0.0.0.0" || "$HOST" == "::" || "$HOST" == "*" ]]; then
  echo "ERROR: refusing to run against a wildcard listener; set AMIN_NODE_LISTEN to its loopback address" >&2
  exit 2
fi
BASE="http://$LISTEN"
SERVICE="${AMIN_XRAY_SERVICE:-xray}"
BEFORE_PID="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || true)"
export AMIN_NODE_TOKEN BASE SERVICE BEFORE_PID

python3 <<'PY'
import json, os, sys, time, uuid, urllib.request, urllib.error, urllib.parse

base = os.environ["BASE"].rstrip("/")
token = os.environ["AMIN_NODE_TOKEN"]
headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}

def request(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    h = dict(headers)
    if data is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            raw = response.read()
    except urllib.error.HTTPError as e:
        detail = e.read(4096).decode(errors="replace")
        raise RuntimeError(f"{method} {path}: HTTP {e.code}: {detail}") from e
    try:
        result = json.loads(raw)
    except Exception as e:
        raise RuntimeError(f"{method} {path}: response was not JSON") from e
    if not result.get("success", False):
        raise RuntimeError(f"{method} {path}: {result.get('msg') or 'Agent returned success=false'}")
    return result.get("obj")

print("== Agent health ==")
health_req = urllib.request.Request(base + "/health", headers={"Accept":"application/json"})
with urllib.request.urlopen(health_req, timeout=5) as r:
    health = json.load(r).get("obj", {})
print("Agent version:", health.get("version", "unknown"))

print("== Authenticated capabilities ==")
caps = request("GET", "/api/v1/capabilities") or {}
print("Xray management:", bool(caps.get("xrayManagement")))
print("Live client management:", bool(caps.get("liveClientManagement")))
print("Features:", ", ".join(caps.get("features", [])))
if not caps.get("xrayManagement") or not caps.get("liveClientManagement"):
    raise SystemExit("FAIL: this Agent build does not expose live Xray client management; install the 0.3.0 candidate first")

print("== System and live inbound list ==")
system = request("GET", "/api/v1/system") or {}
inbounds = request("GET", "/api/v1/inbounds") or []
if not isinstance(inbounds, list):
    raise SystemExit("FAIL: Agent returned an invalid inbound list")
print("Xray inbounds:", len(inbounds))
supported = {"vless", "vmess", "trojan"}
chosen = None
for inbound in inbounds:
    proto = str(inbound.get("protocol", "")).lower()
    tag = str(inbound.get("tag", ""))
    if proto in supported and tag and 1 <= int(inbound.get("port", 0) or 0) <= 65535:
        chosen = inbound
        break
if chosen is None:
    raise SystemExit("FAIL: no VLESS/VMess/Trojan inbound is available for a disposable client test")

proto = str(chosen["protocol"]).lower()
tag = str(chosen["tag"])
email = "amin-smoke-" + uuid.uuid4().hex[:16]
credential = str(uuid.uuid4())
client = {"email": email, "level": 0}
if proto in ("vless", "vmess"):
    client["id"] = credential
else:
    client["password"] = credential

print(f"== Live gRPC add/delete test on {proto} inbound {tag!r} ==")
created = False
try:
    request("POST", "/api/v1/inbounds/" + urllib.parse.quote(tag, safe="") + "/clients", client)
    created = True
    visible = False
    for _ in range(5):
        current = request("GET", "/api/v1/inbounds") or []
        for ib in current:
            if ib.get("tag") == tag:
                settings = ib.get("settings") or {}
                for item in settings.get("clients", []) or []:
                    if str(item.get("email", "")).lower() == email.lower():
                        visible = True
                        break
            if visible:
                break
        if visible:
            break
        time.sleep(0.2)
    if not visible:
        raise RuntimeError("Agent accepted client creation but the client was not visible in the live inbound list")
    print("PASS: client was added and returned by the live inbound API")
finally:
    if created:
        request("DELETE", "/api/v1/inbounds/" + urllib.parse.quote(tag, safe="") + "/clients?email=" + urllib.parse.quote(email, safe=""))
        current = request("GET", "/api/v1/inbounds") or []
        still_present = any(
            ib.get("tag") == tag and any(
                str(item.get("email", "")).lower() == email.lower()
                for item in ((ib.get("settings") or {}).get("clients") or [])
            )
            for ib in current
        )
        if still_present:
            raise RuntimeError("Client deletion returned success but the user is still visible")
        print("PASS: disposable client was deleted and is no longer visible")

print("== Xray process continuity ==")
import subprocess
after = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", os.environ["SERVICE"]], text=True, capture_output=True).stdout.strip()
before = os.environ.get("BEFORE_PID", "").strip()
print("Xray MainPID before:", before or "unavailable")
print("Xray MainPID after: ", after or "unavailable")
if before and after and before != after:
    raise SystemExit("FAIL: Xray MainPID changed during client test (unexpected restart)")
if before and after:
    print("PASS: Xray MainPID did not change")
else:
    print("WARN: could not compare Xray MainPID; verify service name and permissions")
print("RESULT: live Agent/Xray client lifecycle smoke test passed")
PY
