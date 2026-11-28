package xray

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"syscall"
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

func TestAddClientValidatesUUIDAndDuplicateCredentials(t *testing.T) {
	base := map[string]interface{}{"inbounds": []interface{}{
		map[string]interface{}{"tag":"vless-in","protocol":"vless","settings":map[string]interface{}{"clients":[]interface{}{
			map[string]interface{}{"email":"existing","id":"00000000-0000-4000-8000-000000000001"},
		}}},
	}}
	m := testManager(t, base)
	if err := m.AddClient("vless-in", map[string]interface{}{"email":"bad-id","id":"not-a-uuid"}); err == nil { t.Fatal("expected malformed UUID to be rejected") }
	if err := m.AddClient("vless-in", map[string]interface{}{"email":"duplicate-id","id":"00000000-0000-4000-8000-000000000001"}); err == nil { t.Fatal("expected duplicate UUID to be rejected") }
	if err := m.AddClient("vless-in", map[string]interface{}{"email":"bad email","id":"00000000-0000-4000-8000-000000000002"}); err == nil { t.Fatal("expected whitespace in email to be rejected") }
}
func TestValidClientEmail(t *testing.T) {
	if !validClientEmail("missing@example.com") {
		t.Fatal("valid email was rejected")
	}
	for _, email := range []string{"", " leading@example.com", "trailing@example.com ", "line\nbreak@example.com", "tab\t@example.com"} {
		if validClientEmail(email) {
			t.Fatalf("invalid email %q was accepted", email)
		}
	}
}

func TestUpdateClientValidatesPatchAndPreservesIdentity(t *testing.T) {
	m := testManager(t, map[string]interface{}{"inbounds": []interface{}{
		map[string]interface{}{"tag":"vless-in","protocol":"vless","settings":map[string]interface{}{"clients":[]interface{}{
			map[string]interface{}{"email":"alice@example.com","id":"00000000-0000-4000-8000-000000000001","flow":"xtls-rprx-vision"},
		}}},
	}})
	if err := m.UpdateClient("vless-in", "alice@example.com", map[string]interface{}{}); err == nil {
		t.Fatal("expected empty patch to be rejected")
	}
	if err := m.UpdateClient("vless-in", "alice@example.com", map[string]interface{}{"email":"mallory"}); err == nil {
		t.Fatal("expected identity-changing patch to be rejected")
	}
	if err := m.UpdateClient("vless-in", "alice@example.com", map[string]interface{}{"id":"not-a-uuid"}); err == nil {
		t.Fatal("expected invalid replacement UUID to be rejected")
	}
	if err := m.UpdateClient("vless-in", "missing@example.com", map[string]interface{}{"flow":"xtls-rprx-vision"}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing client error, got %v", err)
	}
	if err := m.UpdateClient("vless-in", "alice@example.com", map[string]interface{}{"flow":"xtls-rprx-vision"}); err == nil {
		t.Fatal("expected missing Xray binary to prevent applying a client update in this unit test")
	}
	inbounds, err := m.ListInbounds()
	if err != nil { t.Fatal(err) }
	clients := inbounds[0]["settings"].(map[string]interface{})["clients"].([]interface{})
	if clients[0].(map[string]interface{})["id"] != "00000000-0000-4000-8000-000000000001" {
		t.Fatal("failed update changed the original client credential")
	}
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

func TestPreserveFileMetadata(t *testing.T) {
	dir := t.TempDir()
	originalPath := filepath.Join(dir, "original.json")
	stagedPath := filepath.Join(dir, "staged.json")
	if err := os.WriteFile(originalPath, []byte("{}"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(originalPath, 0640); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stagedPath, []byte("{\"inbounds\":[]}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := preserveFileMetadata(stagedPath, info); err != nil {
		t.Fatal(err)
	}
	got, err := os.Stat(stagedPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode().Perm() != info.Mode().Perm() {
		t.Fatalf("permissions not preserved: got %04o want %04o", got.Mode().Perm(), info.Mode().Perm())
	}
	want, ok := info.Sys().(*syscall.Stat_t)
	if !ok { t.Fatal("original metadata is not syscall.Stat_t") }
	have, ok := got.Sys().(*syscall.Stat_t)
	if !ok { t.Fatal("staged metadata is not syscall.Stat_t") }
	if have.Uid != want.Uid || have.Gid != want.Gid {
		t.Fatalf("ownership not preserved: got %d:%d want %d:%d", have.Uid, have.Gid, want.Uid, want.Gid)
	}
}
