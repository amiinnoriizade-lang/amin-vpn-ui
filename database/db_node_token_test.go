package database

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/nodetoken"
)

func TestMigrateNodeAPITokensEncryptsLegacyRows(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VPNUI_NODE_TOKEN_KEY_FILE", filepath.Join(dir, "node-token.key"))
	if err := InitDB(filepath.Join(dir, "vpn-ui.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = CloseDB()
		db = nil
	})

	const plain = "legacy-node-api-token"
	node := model.Node{Name: "legacy-test", Scheme: "https", Address: "127.0.0.1", Port: 2053, ApiToken: plain}
	if err := db.Create(&node).Error; err != nil {
		t.Fatal(err)
	}
	if err := migrateNodeAPITokens(); err != nil {
		t.Fatal(err)
	}
	var stored model.Node
	if err := db.First(&stored, node.Id).Error; err != nil {
		t.Fatal(err)
	}
	if stored.ApiToken == plain || !strings.HasPrefix(stored.ApiToken, "enc:v1:") {
		t.Fatalf("legacy token was not encrypted: %q", stored.ApiToken)
	}
	got, err := nodetoken.Decrypt(stored.ApiToken)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Fatalf("decrypted token = %q, want original", got)
	}
}
