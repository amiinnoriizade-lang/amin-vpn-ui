package job

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestProbeNodeBlocksPrivateAddressesByDefault(t *testing.T) {
	n := model.Node{
		Scheme: "http", Address: "127.0.0.1", Port: 2053,
		Enable: true, TlsVerifyMode: "system",
	}
	patch := probeNode(n)
	if patch["status"] != "offline" {
		t.Fatalf("expected private address to be blocked, got status %v", patch["status"])
	}
	if !strings.Contains(patch["last_error"].(string), "private or reserved") {
		t.Fatalf("expected private-address policy error, got %v", patch["last_error"])
	}
}

func TestProbeNodeReadsStatusAndUsesBearerToken(t *testing.T) {
	var gotPath, gotAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"obj": map[string]any{
				"cpu": 17.5,
				"mem": map[string]any{"current": 256, "total": 1024},
				"panelVersion": "test-panel",
				"uptime": 1234,
				"xray": map[string]any{"version": "test-xray", "state": "running"},
			},
		})
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	n := model.Node{
		Scheme: "http", Address: host, Port: port, BasePath: "/gateway",
		ApiToken: "test-secret", Enable: true, AllowPrivateAddress: true,
		TlsVerifyMode: "system",
	}
	patch := probeNode(n)
	if patch["status"] != "online" {
		t.Fatalf("expected online status, got %v (error: %v)", patch["status"], patch["last_error"])
	}
	if gotPath != "/gateway/panel/api/server/status" {
		t.Fatalf("unexpected request path: %q", gotPath)
	}
	if gotAuthorization != "Bearer test-secret" {
		t.Fatalf("unexpected Authorization header: %q", gotAuthorization)
	}
	if patch["cpu_pct"] != 17.5 || patch["mem_pct"] != 25.0 {
		t.Fatalf("unexpected resource metrics: cpu=%v mem=%v", patch["cpu_pct"], patch["mem_pct"])
	}
	if patch["panel_version"] != "test-panel" || patch["xray_version"] != "test-xray" || patch["xray_state"] != "running" {
		t.Fatalf("unexpected version/state metrics: %#v", patch)
	}
	if patch["uptime_secs"] != uint64(1234) {
		t.Fatalf("unexpected uptime: %v", patch["uptime_secs"])
	}
}
