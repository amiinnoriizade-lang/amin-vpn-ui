package controller

import (
	"crypto/ecdh"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/web/job"
)

func TestBuildNativeAgentShareLinkVLESSWebSocketTLS(t *testing.T) {
	inbound := job.NativeAgentInbound{
		Tag: "amin-vless-443",
		Port: 443,
		Protocol: "vless",
		StreamSettings: []byte(`{
			"network":"ws",
			"security":"tls",
			"wsSettings":{"path":"/edge","headers":{"Host":"cdn.example.test"}},
			"tlsSettings":{"serverName":"cdn.example.test","fingerprint":"chrome","alpn":["h2","http/1.1"]}
		}`),
	}
	client := map[string]any{
		"email":"amin-user-01",
		"id":"00000000-0000-4000-8000-000000000001",
		"flow":"xtls-rprx-vision",
	}
	link, protocol, remark, err := buildNativeAgentShareLink("vpn.example.test", "node-1", inbound, client, "amin-user-01")
	if err != nil {
		t.Fatalf("build share link: %v", err)
	}
	if protocol != "vless" || remark != inbound.Tag {
		t.Fatalf("unexpected metadata: protocol=%q remark=%q", protocol, remark)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse generated URI: %v", err)
	}
	if parsed.Scheme != "vless" || parsed.Host != "vpn.example.test:443" {
		t.Fatalf("unexpected URI endpoint: %s", link)
	}
	if parsed.User == nil || parsed.User.Username() != client["id"] {
		t.Fatalf("UUID missing from URI: %s", link)
	}
	q := parsed.Query()
	for key, want := range map[string]string{
		"type":"ws", "security":"tls", "encryption":"none",
		"flow":"xtls-rprx-vision", "sni":"cdn.example.test",
		"fp":"chrome", "path":"/edge", "host":"cdn.example.test",
		"alpn":"h2,http/1.1",
	} {
		if got := q.Get(key); got != want {
			t.Errorf("query %s = %q, want %q", key, got, want)
		}
	}
}

func TestBuildNativeAgentShareLinkRealityDerivesPublicKey(t *testing.T) {
	privateBytes := make([]byte, 32)
	for i := range privateBytes {
		privateBytes[i] = byte(i + 1)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	privateEncoded := base64.RawURLEncoding.EncodeToString(privateBytes)
	wantPublic := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())

	inbound := job.NativeAgentInbound{
		Tag: "amin-reality-8443",
		Port: 8443,
		Protocol: "vless",
		StreamSettings: []byte(`{
			"network":"tcp",
			"security":"reality",
			"realitySettings":{
				"privateKey":"` + privateEncoded + `",
				"serverNames":["reality.example.test"],
				"shortIds":["a1b2c3d4"]
			}
		}`),
	}
	client := map[string]any{
		"email":"reality-user",
		"id":"00000000-0000-4000-8000-000000000002",
	}
	link, _, _, err := buildNativeAgentShareLink("203.0.113.10", "node-reality", inbound, client, "reality-user")
	if err != nil {
		t.Fatalf("build Reality share link: %v", err)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse generated Reality URI: %v", err)
	}
	q := parsed.Query()
	if got := q.Get("pbk"); got != wantPublic {
		t.Fatalf("Reality public key = %q, want derived public key %q", got, wantPublic)
	}
	if q.Get("sni") != "reality.example.test" || q.Get("sid") != "a1b2c3d4" {
		t.Fatalf("Reality server name or short ID missing: %s", link)
	}
	if strings.Contains(link, privateEncoded) {
		t.Fatal("generated client URI leaked the server private key")
	}
}
