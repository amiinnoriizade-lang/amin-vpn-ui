package xray

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testManager(t *testing.T, cfg map[string]interface{}) *ConfigManager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	data, err := json.Marshal(cfg)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, data, 0600); err != nil { t.Fatal(err) }
	return &ConfigManager{Path: path, XrayBinary: "/missing/xray", Service: "xray"}
}

func TestListInbounds(t *testing.T) {
	m := testManager(t, map[string]interface{}{"inbounds": []interface{}{map[string]interface{}{"tag":"edge","protocol":"vless","port":443}}})
	got, err := m.ListInbounds()
	if err != nil { t.Fatal(err) }
	if len(got) != 1 || got[0]["tag"] != "edge" { t.Fatalf("unexpected inbounds: %#v", got) }
}

func TestAddInboundRejectsInvalidInputBeforeTouchingConfig(t *testing.T) {
	m := testManager(t, map[string]interface{}{"inbounds": []interface{}{}})
	err := m.AddInbound(Inbound{Tag:"bad tag", Port:443, Protocol:"vless", Settings:map[string]interface{}{"clients":[]interface{}{}}})
	if err == nil { t.Fatal("expected invalid tag error") }
	err = m.AddInbound(Inbound{Tag:"valid", Port:70000, Protocol:"vless", Settings:map[string]interface{}{"clients":[]interface{}{}}})
	if err == nil { t.Fatal("expected invalid port error") }
	err = m.AddInbound(Inbound{Tag:"valid", Port:443, Protocol:"ftp", Settings:map[string]interface{}{}})
	if err == nil { t.Fatal("expected unsupported protocol error") }
	got, readErr := m.ListInbounds()
	if readErr != nil { t.Fatal(readErr) }
	if len(got) != 0 { t.Fatalf("invalid requests changed config: %#v", got) }
}

func TestAddClientRequiresProtocolCredential(t *testing.T) {
	m := testManager(t, map[string]interface{}{"inbounds": []interface{}{
		map[string]interface{}{"tag":"vless-in","protocol":"vless","settings":map[string]interface{}{"clients":[]interface{}{}}},
	}})
	err := m.AddClient("vless-in", map[string]interface{}{"email":"test-user"})
	if err == nil { t.Fatal("expected UUID validation error") }
}

func TestDeleteMissingInbound(t *testing.T) {
	m := testManager(t, map[string]interface{}{"inbounds": []interface{}{}})
	err := m.DeleteInbound("not-found")
	if !errors.Is(err, os.ErrNotExist) { t.Fatalf("expected not-exist, got %v", err) }
}

func TestAddClientRejectsUnknownFields(t *testing.T) {
	m := testManager(t, map[string]interface{}{"inbounds": []interface{}{}})
	err := m.AddClient("in", map[string]interface{}{"email":"x","shell":"rm -rf /"})
	if err == nil { t.Fatal("expected unknown field error") }
}
