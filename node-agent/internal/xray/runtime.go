package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	shadowsocks2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type runtimeAPI interface {
	AddUser(protocol, tag string, client map[string]interface{}) error
	RemoveUser(tag, email string) error
	Close() error
}

type grpcRuntimeAPI struct {
	conn   *grpc.ClientConn
	client command.HandlerServiceClient
}

type runtimeClient struct {
	Tag      string                 `json:"tag"`
	Protocol string                 `json:"protocol"`
	Client   map[string]interface{} `json:"client"`
}

type runtimeState struct {
	Version int `json:"version"`
	CorePID int `json:"corePid,omitempty"`
	Clients []runtimeClient `json:"clients"`
}

// RuntimeManager stores users independently of the Xray JSON config and applies
// mutations through Xray's HandlerService. Client operations never restart Xray.
type RuntimeManager struct {
	config *ConfigManager
	api    runtimeAPI
	path   string
	mu     sync.Mutex
	state  runtimeState
}

func apiPort(cfg map[string]interface{}) (int, error) {
	apiCfg, ok := cfg["api"].(map[string]interface{})
	if !ok {
		return 0, errors.New("Xray API is not configured")
	}
	services, ok := apiCfg["services"].([]interface{})
	if !ok {
		return 0, errors.New("Xray API services are not configured")
	}
	handlerEnabled := false
	for _, raw := range services {
		if s, ok := raw.(string); ok && s == "HandlerService" {
			handlerEnabled = true
		}
	}
	if !handlerEnabled {
		return 0, errors.New("Xray HandlerService is not enabled")
	}
	inbounds, err := inboundList(cfg)
	if err != nil {
		return 0, err
	}
	for _, raw := range inbounds {
		in, ok := raw.(map[string]interface{})
		if !ok || stringField(in, "tag") != "api" {
			continue
		}
		port, ok := in["port"].(float64)
		if !ok || port < 1 || port > 65535 {
			return 0, errors.New("Xray API inbound has an invalid port")
		}
		return int(port), nil
	}
	return 0, errors.New("Xray API inbound with tag api was not found")
}

func NewRuntimeManager(config *ConfigManager, statePath string) (*RuntimeManager, error) {
	if config == nil {
		return nil, errors.New("Xray config manager is unavailable")
	}
	if !filepath.IsAbs(statePath) {
		return nil, errors.New("runtime state path must be absolute")
	}
	cfg, err := config.read()
	if err != nil {
		return nil, err
	}
	port, err := apiPort(cfg)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("create Xray gRPC client: %w", err)
	}
	api := &grpcRuntimeAPI{conn: conn, client: command.NewHandlerServiceClient(conn)}
	m := &RuntimeManager{config: config, api: api, path: filepath.Clean(statePath), state: runtimeState{Version: 1, Clients: []runtimeClient{}}}
	if err := m.load(); err != nil {
		conn.Close()
		return nil, err
	}
	return m, nil
}

func (a *grpcRuntimeAPI) Close() error {
	if a.conn == nil {
		return nil
	}
	return a.conn.Close()
}

func (a *grpcRuntimeAPI) AddUser(proto, tag string, client map[string]interface{}) error {
	email := stringField(client, "email")
	var account *serial.TypedMessage
	switch proto {
	case "vless":
		id := stringField(client, "id")
		if !uuidPattern.MatchString(id) {
			return errors.New("VLESS client requires a valid UUID")
		}
		account = serial.ToTypedMessage(&vless.Account{Id: id, Flow: stringField(client, "flow")})
	case "vmess":
		id := stringField(client, "id")
		if !uuidPattern.MatchString(id) {
			return errors.New("VMess client requires a valid UUID")
		}
		account = serial.ToTypedMessage(&vmess.Account{Id: id})
	case "trojan":
		password := stringField(client, "password")
		if password == "" {
			return errors.New("Trojan client requires a password")
		}
		account = serial.ToTypedMessage(&trojan.Account{Password: password})
	case "shadowsocks":
		password := stringField(client, "password")
		if password == "" {
			return errors.New("Shadowsocks client requires a password")
		}
		cipher := stringField(client, "cipher")
		switch cipher {
		case "chacha20-poly1305", "chacha20-ietf-poly1305":
			account = serial.ToTypedMessage(&shadowsocks.Account{Password: password, CipherType: shadowsocks.CipherType_CHACHA20_POLY1305})
		case "xchacha20-poly1305", "xchacha20-ietf-poly1305":
			account = serial.ToTypedMessage(&shadowsocks.Account{Password: password, CipherType: shadowsocks.CipherType_XCHACHA20_POLY1305})
		default:
			account = serial.ToTypedMessage(&shadowsocks2022.ServerConfig{Key: password, Email: email})
		}
	default:
		return fmt.Errorf("unsupported protocol for live client management: %s", proto)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err := a.client.AlterInbound(ctx, &command.AlterInboundRequest{
		Tag: tag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{User: &protocol.User{Email: email, Account: account}}),
	})
	if err != nil {
		return fmt.Errorf("Xray AddUser failed: %w", err)
	}
	return nil
}

func (a *grpcRuntimeAPI) RemoveUser(tag, email string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err := a.client.AlterInbound(ctx, &command.AlterInboundRequest{
		Tag: tag,
		Operation: serial.ToTypedMessage(&command.RemoveUserOperation{Email: email}),
	})
	if err != nil {
		return fmt.Errorf("Xray RemoveUser failed: %w", err)
	}
	return nil
}

func (m *RuntimeManager) load() error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0700); err != nil {
		return fmt.Errorf("create runtime state directory: %w", err)
	}
	data, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return m.saveLocked()
	}
	if err != nil {
		return fmt.Errorf("read runtime state: %w", err)
	}
	var state runtimeState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode runtime state: %w", err)
	}
	if state.Version != 1 || state.Clients == nil {
		return errors.New("unsupported or invalid runtime state file")
	}
	m.state = state
	return nil
}

func (m *RuntimeManager) saveLocked() error {
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.path), ".amin-runtime-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, m.path)
}

func runtimeKey(tag, email string) string { return tag + "\x00" + email }

func (m *RuntimeManager) ListInbounds() ([]map[string]interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inbounds, err := m.config.ListInbounds()
	if err != nil {
		return nil, err
	}
	byTag := make(map[string]map[string]interface{}, len(inbounds))
	for _, in := range inbounds {
		byTag[stringField(in, "tag")] = in
	}
	for _, entry := range m.state.Clients {
		in := byTag[entry.Tag]
		if in == nil {
			continue
		}
		settings, ok := in["settings"].(map[string]interface{})
		if !ok {
			continue
		}
		clients, _ := settings["clients"].([]interface{})
		duplicate := false
		for _, raw := range clients {
			if existing, ok := raw.(map[string]interface{}); ok && stringField(existing, "email") == stringField(entry.Client, "email") {
				duplicate = true
				break
			}
		}
		if !duplicate {
			settings["clients"] = append(clients, entry.Client)
		}
	}
	return inbounds, nil
}

func (m *RuntimeManager) AddClient(tag string, client map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.api == nil {
		return errors.New("Xray live API is unavailable")
	}
	email := stringField(client, "email")
	if email == "" || strings.TrimSpace(email) != email || strings.ContainsAny(email, " \t\r\n") || len(email) > 128 {
		return errors.New("client email is required and must not contain whitespace")
	}
	inbounds, err := m.config.ListInbounds()
	if err != nil {
		return err
	}
	var proto string
	var staticClients []interface{}
	found := false
	for _, in := range inbounds {
		if stringField(in, "tag") != tag {
			continue
		}
		found = true
		proto = stringField(in, "protocol")
		if settings, ok := in["settings"].(map[string]interface{}); ok {
			staticClients, _ = settings["clients"].([]interface{})
		}
		break
	}
	if !found {
		return os.ErrNotExist
	}
	for _, raw := range staticClients {
		if existing, ok := raw.(map[string]interface{}); ok && stringField(existing, "email") == email {
			return errors.New("client email already exists in Xray config")
		}
	}
	key := runtimeKey(tag, email)
	for _, entry := range m.state.Clients {
		if runtimeKey(entry.Tag, stringField(entry.Client, "email")) == key {
			return errors.New("client already exists")
		}
	}
	if proto == "vless" || proto == "vmess" {
		if !uuidPattern.MatchString(stringField(client, "id")) {
			return errors.New("client requires a valid UUID")
		}
	} else if proto == "trojan" || proto == "shadowsocks" {
		if stringField(client, "password") == "" {
			return errors.New("client requires a password")
		}
	} else {
		return fmt.Errorf("live client management is unsupported for protocol %s", proto)
	}
	entry := runtimeClient{Tag: tag, Protocol: proto, Client: client}
	m.state.Clients = append(m.state.Clients, entry)
	if err := m.saveLocked(); err != nil {
		m.state.Clients = m.state.Clients[:len(m.state.Clients)-1]
		return fmt.Errorf("persist client before applying: %w", err)
	}
	if err := m.api.AddUser(proto, tag, client); err != nil {
		m.state.Clients = m.state.Clients[:len(m.state.Clients)-1]
		if saveErr := m.saveLocked(); saveErr != nil {
			return fmt.Errorf("%v; also failed to roll back state: %w", err, saveErr)
		}
		return err
	}
	return nil
}

func (m *RuntimeManager) DeleteClient(tag, email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.api == nil {
		return errors.New("Xray live API is unavailable")
	}
	for i, entry := range m.state.Clients {
		if entry.Tag != tag || stringField(entry.Client, "email") != email {
			continue
		}
		if err := m.api.RemoveUser(tag, email); err != nil {
			return err
		}
		previous := entry
		m.state.Clients = append(m.state.Clients[:i], m.state.Clients[i+1:]...)
		if err := m.saveLocked(); err != nil {
			m.state.Clients = append(m.state.Clients, previous)
			_ = m.api.AddUser(previous.Protocol, previous.Tag, previous.Client)
			return fmt.Errorf("persist client deletion: %w", err)
		}
		return nil
	}
	return errors.New("client is not managed by AMIN runtime state; legacy static clients are not deleted by live API")
}

func (m *RuntimeManager) Close() error {
	if m.api == nil {
		return nil
	}
	return m.api.Close()
}


func (m *RuntimeManager) ReconcileIfChanged() error {
	out, err := exec.Command("systemctl", "show", m.config.Service, "--property=MainPID", "--value").Output()
	if err != nil {
		return fmt.Errorf("read Xray MainPID: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		return errors.New("Xray service does not have a running MainPID")
	}
	return m.reconcileForPID(pid)
}

func (m *RuntimeManager) reconcileForPID(pid int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.api == nil {
		return errors.New("Xray live API is unavailable")
	}
	if pid <= 0 {
		return errors.New("invalid Xray MainPID")
	}
	if pid == m.state.CorePID {
		return nil
	}
	for _, entry := range m.state.Clients {
		if err := m.api.AddUser(entry.Protocol, entry.Tag, entry.Client); err != nil {
			if !strings.Contains(strings.ToLower(err.Error()), "already") {
				return fmt.Errorf("restore runtime client %s on inbound %s: %w", stringField(entry.Client, "email"), entry.Tag, err)
			}
		}
	}
	previousPID := m.state.CorePID
	m.state.CorePID = pid
	if err := m.saveLocked(); err != nil {
		m.state.CorePID = previousPID
		return fmt.Errorf("persist reconciled Xray PID: %w", err)
	}
	return nil
}
