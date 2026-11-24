package model

import (
 "encoding/json"
 "strings"
 "testing"
)

func TestNodeTableName(t *testing.T) {
 if got := (Node{}).TableName(); got != "nodes" { t.Fatalf("TableName() = %q, want nodes", got) }
}

func TestNodeApiTokenIsNeverSerialized(t *testing.T) {
 b, err := json.Marshal(Node{Name:"edge-1", ApiToken:"secret-token"})
 if err != nil { t.Fatal(err) }
 if strings.Contains(string(b), "secret-token") || strings.Contains(string(b), "apiToken") {
  t.Fatalf("node API token leaked in JSON: %s", b)
 }
}
