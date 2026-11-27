package xray

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func statsConfig(listen string, services []interface{}) map[string]interface{} {
	return map[string]interface{}{
		"api": map[string]interface{}{"tag":"api","services":services},
		"inbounds": []interface{}{
			map[string]interface{}{"tag":"api","listen":listen,"port":10085,"protocol":"dokodemo-door"},
		},
	}
}

func TestStatsAPIAddressRequiresLoopbackStatsService(t *testing.T) {
	m := testManager(t, statsConfig("127.0.0.1", []interface{}{"StatsService"}))
	address, err := m.StatsAPIAddress()
	if err != nil { t.Fatal(err) }
	if address != "127.0.0.1:10085" { t.Fatalf("address = %q", address) }

	m = testManager(t, statsConfig("0.0.0.0", []interface{}{"StatsService"}))
	if _, err := m.StatsAPIAddress(); err == nil { t.Fatal("public API listener must be rejected") }

	m = testManager(t, statsConfig("127.0.0.1", []interface{}{"HandlerService"}))
	if _, err := m.StatsAPIAddress(); err == nil { t.Fatal("missing StatsService must be rejected") }
}

func TestQueryUserTrafficParsesOnlyUserTrafficCounters(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	config, _ := json.Marshal(statsConfig("127.0.0.1", []interface{}{"StatsService"}))
	if err := os.WriteFile(configPath, config, 0600); err != nil { t.Fatal(err) }

	binary := filepath.Join(dir, "xray")
	script := `#!/bin/sh
printf '%s\n' '{"stat":[{"name":"user>>>alice@example.com>>>traffic>>>uplink","value":"1234"},{"name":"user>>>alice@example.com>>>traffic>>>downlink","value":"5678"},{"name":"inbound>>>api>>>traffic>>>uplink","value":"99"},{"name":"user>>>bob@example.com>>>online","value":"1"}]}'
`
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil { t.Fatal(err) }
	m := &ConfigManager{Path:configPath, XrayBinary:binary}

	got, err := m.QueryUserTraffic(context.Background())
	if err != nil { t.Fatal(err) }
	want := []UserTraffic{{Email:"alice@example.com",Up:1234,Down:5678}}
	if len(got) != 1 || !reflect.DeepEqual(got[0], want[0]) {
		t.Fatalf("traffic = %#v, want %#v", got, want)
	}
}
