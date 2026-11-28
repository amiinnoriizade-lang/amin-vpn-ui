package controller

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/web/job"
)

func TestBuildNativeAgentShadowsocksShareLink(t *testing.T) {
	inbound := job.NativeAgentInbound{
		Tag: "ss-in",
		Port: 8388,
		Protocol: "shadowsocks",
		Settings: json.RawMessage(`{"method":"aes-128-gcm","clients":[{"email":"alice","password":"secret-value"}]}`),
		StreamSettings: json.RawMessage(`{"network":"tcp","security":"none"}`),
	}
	link, protocol, remark, err := buildNativeAgentShareLink("vpn.example.com", "node-1", inbound, map[string]any{
		"email": "alice",
		"password": "secret-value",
	}, "alice")
	if err != nil {
		t.Fatalf("build share link: %v", err)
	}
	if protocol != "shadowsocks" || remark != "ss-in" {
		t.Fatalf("unexpected metadata: protocol=%q remark=%q", protocol, remark)
	}
	if !strings.HasPrefix(link, "ss://") || !strings.Contains(link, "@vpn.example.com:8388#") {
		t.Fatalf("unexpected Shadowsocks URI: %s", link)
	}
	encoded := strings.TrimPrefix(strings.SplitN(link, "@", 2)[0], "ss://")
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode Shadowsocks user info: %v", err)
	}
	if string(decoded) != "aes-128-gcm:secret-value" {
		t.Fatalf("unexpected Shadowsocks credential payload: %q", decoded)
	}
}

func TestBuildNativeAgentShadowsocksRequiresMethod(t *testing.T) {
	inbound := job.NativeAgentInbound{
		Tag: "ss-in",
		Port: 8388,
		Protocol: "shadowsocks",
		Settings: json.RawMessage(`{"clients":[]}`),
	}
	_, _, _, err := buildNativeAgentShareLink("vpn.example.com", "node-1", inbound, map[string]any{
		"email": "alice",
		"password": "secret-value",
	}, "alice")
	if err == nil || !strings.Contains(err.Error(), "روش رمزنگاری") {
		t.Fatalf("expected a clear missing-method error, got %v", err)
	}
}
