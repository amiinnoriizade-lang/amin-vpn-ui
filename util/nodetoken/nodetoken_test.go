package nodetoken

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptDecryptAndLegacyCompatibility(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "node-token.key")
	t.Setenv("VPNUI_NODE_TOKEN_KEY_FILE", keyPath)

	const token = "a-long-node-token-that-must-not-be-stored-in-plain-text"
	encrypted, err := Encrypt(token)
	if err != nil { t.Fatal(err) }
	if encrypted == token || !strings.HasPrefix(encrypted, prefix) {
		t.Fatalf("token was not encrypted: %q", encrypted)
	}
	if strings.Contains(encrypted, token) { t.Fatal("ciphertext contains plaintext token") }
	got, err := Decrypt(encrypted)
	if err != nil { t.Fatal(err) }
	if got != token { t.Fatalf("decrypted token = %q, want original", got) }
	if got, err := Decrypt("legacy-plain-token"); err != nil || got != "legacy-plain-token" {
		t.Fatalf("legacy plaintext compatibility: got %q, err %v", got, err)
	}
	if info, err := os.Stat(keyPath); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0600 {
		t.Fatalf("key permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	t.Setenv("VPNUI_NODE_TOKEN_KEY_FILE", filepath.Join(t.TempDir(), "node-token.key"))
	encrypted, err := Encrypt("secret-token")
	if err != nil { t.Fatal(err) }
	changed := encrypted[:len(encrypted)-1] + "A"
	if _, err := Decrypt(changed); err == nil {
		t.Fatal("expected tampered ciphertext to be rejected")
	}
}

func TestEncryptDoesNotDoubleEncrypt(t *testing.T) {
	t.Setenv("VPNUI_NODE_TOKEN_KEY_FILE", filepath.Join(t.TempDir(), "node-token.key"))
	once, err := Encrypt("secret-token")
	if err != nil { t.Fatal(err) }
	twice, err := Encrypt(once)
	if err != nil { t.Fatal(err) }
	if twice != once { t.Fatal("already encrypted token changed") }
}

func TestRejectsOverPermissiveKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-token.key")
	if err := os.WriteFile(path, make([]byte, 32), 0644); err != nil { t.Fatal(err) }
	t.Setenv("VPNUI_NODE_TOKEN_KEY_FILE", path)
	if _, err := Encrypt("secret-token"); err == nil {
		t.Fatal("expected permissive key file to be rejected")
	}
}
