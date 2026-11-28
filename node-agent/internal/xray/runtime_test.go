package xray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type fakeRuntimeAPI struct {
	added, removed []string
	addErr, removeErr error
}
func (f *fakeRuntimeAPI) AddUser(proto, tag string, client map[string]interface{}) error {
	f.added = append(f.added, tag+":"+stringField(client, "email"))
	return f.addErr
}
func (f *fakeRuntimeAPI) RemoveUser(tag, email string) error {
	f.removed = append(f.removed, tag+":"+email)
	return f.removeErr
}
func (f *fakeRuntimeAPI) Close() error { return nil }

func runtimeTestManager(t *testing.T) (*ConfigManager, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := map[string]interface{}{
		"api": map[string]interface{}{"services": []interface{}{"HandlerService"}},
		"inbounds": []interface{}{
			map[string]interface{}{"tag":"api","port":10085,"protocol":"dokodemo-door","settings":map[string]interface{}{"address":"127.0.0.1"}},
			map[string]interface{}{"tag":"edge","port":443,"protocol":"vless","settings":map[string]interface{}{"clients":[]interface{}{},"decryption":"none"}},
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, data, 0600); err != nil { t.Fatal(err) }
	return &ConfigManager{Path:path, XrayBinary:"/missing/xray", Service:"xray"}, path, data
}

func TestAPIportRequiresHandlerAndTaggedInbound(t *testing.T) {
	cfg := map[string]interface{}{
		"api": map[string]interface{}{"services":[]interface{}{"HandlerService"}},
		"inbounds": []interface{}{map[string]interface{}{"tag":"api","port":10085}},
	}
	port, err := apiPort(cfg)
	if err != nil || port != 10085 { t.Fatalf("port=%d err=%v", port, err) }
	cfg["api"] = map[string]interface{}{"services":[]interface{}{"StatsService"}}
	if _, err := apiPort(cfg); err == nil { t.Fatal("expected HandlerService requirement") }
}

func TestRuntimeClientMutationUsesAPIAndDoesNotRewriteConfig(t *testing.T) {
	manager, configPath, original := runtimeTestManager(t)
	api := &fakeRuntimeAPI{}
	m := &RuntimeManager{config:manager, api:api, path:filepath.Join(t.TempDir(),"state.json"), state:runtimeState{Version:1,Clients:[]runtimeClient{}}}
	if err := m.load(); err != nil { t.Fatal(err) }
	client := map[string]interface{}{"email":"runtime-user","id":"00000000-0000-4000-8000-000000000123","level":0,"flow":""}
	if err := m.AddClient("edge", client); err != nil { t.Fatal(err) }
	if len(api.added) != 1 { t.Fatalf("expected one gRPC add, got %#v", api.added) }
	afterAdd, err := os.ReadFile(configPath)
	if err != nil { t.Fatal(err) }
	if string(afterAdd) != string(original) { t.Fatal("client creation rewrote Xray config") }
	inbounds, err := m.ListInbounds()
	if err != nil { t.Fatal(err) }
	settings := inbounds[1]["settings"].(map[string]interface{})
	clients := settings["clients"].([]interface{})
	if len(clients) != 1 || stringField(clients[0].(map[string]interface{}),"email") != "runtime-user" { t.Fatalf("runtime user missing from inbound listing: %#v", clients) }
	if err := m.DeleteClient("edge","runtime-user"); err != nil { t.Fatal(err) }
	if len(api.removed) != 1 { t.Fatalf("expected one gRPC removal, got %#v", api.removed) }
	afterDelete, err := os.ReadFile(configPath)
	if err != nil { t.Fatal(err) }
	if string(afterDelete) != string(original) { t.Fatal("client deletion rewrote Xray config") }
}

func TestRuntimeStateSurvivesManagerRecreation(t *testing.T) {
	manager, _, _ := runtimeTestManager(t)
	statePath := filepath.Join(t.TempDir(),"state.json")
	api := &fakeRuntimeAPI{}
	first := &RuntimeManager{config:manager,api:api,path:statePath,state:runtimeState{Version:1,Clients:[]runtimeClient{}}}
	if err := first.load(); err != nil { t.Fatal(err) }
	client := map[string]interface{}{"email":"persistent","id":"00000000-0000-4000-8000-000000000124"}
	if err := first.AddClient("edge",client); err != nil { t.Fatal(err) }
	second := &RuntimeManager{config:manager,api:&fakeRuntimeAPI{},path:statePath,state:runtimeState{Version:1,Clients:[]runtimeClient{}}}
	if err := second.load(); err != nil { t.Fatal(err) }
	if len(second.state.Clients) != 1 || stringField(second.state.Clients[0].Client,"email") != "persistent" { t.Fatalf("state was not restored: %#v", second.state) }
	info, err := os.Stat(statePath)
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0600 { t.Fatalf("state permissions=%o, want 600", info.Mode().Perm()) }
}

func TestRuntimeReconcilesOnlyWhenCorePIDChanges(t *testing.T) {
	manager, _, _ := runtimeTestManager(t)
	api := &fakeRuntimeAPI{}
	m := &RuntimeManager{
		config: manager,
		api: api,
		path: filepath.Join(t.TempDir(), "state.json"),
		state: runtimeState{Version:1, CorePID:100, Clients:[]runtimeClient{
			{Tag:"edge", Protocol:"vless", Client:map[string]interface{}{"email":"persisted","id":"00000000-0000-4000-8000-000000000125"}},
		}},
	}
	if err := m.saveLocked(); err != nil { t.Fatal(err) }
	if err := m.reconcileForPID(100); err != nil { t.Fatal(err) }
	if len(api.added) != 0 { t.Fatalf("same Xray PID must not duplicate users: %#v", api.added) }
	if err := m.reconcileForPID(101); err != nil { t.Fatal(err) }
	if len(api.added) != 1 || api.added[0] != "edge:persisted" { t.Fatalf("changed Xray PID did not restore clients: %#v", api.added) }
	if m.state.CorePID != 101 { t.Fatalf("saved core PID=%d, want 101", m.state.CorePID) }
}
