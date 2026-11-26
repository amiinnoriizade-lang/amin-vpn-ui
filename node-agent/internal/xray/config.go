package xray

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var serviceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.@-]{1,128}$`)

// ConfigManager owns one fixed Xray config path. All changes are validated by
// the Xray binary before the live file is replaced, and the service is restarted
// only after the atomic replacement succeeds.
type ConfigManager struct {
	Path       string
	XrayBinary string
	Service    string
	mu         sync.Mutex
}

type Inbound struct {
	Tag            string                 `json:"tag"`
	Port           int                    `json:"port"`
	Listen         string                 `json:"listen,omitempty"`
	Protocol       string                 `json:"protocol"`
	Settings       map[string]interface{} `json:"settings"`
	StreamSettings map[string]interface{} `json:"streamSettings,omitempty"`
	Sniffing       map[string]interface{} `json:"sniffing,omitempty"`
}

func NewConfigManager() (*ConfigManager, error) {
	path := strings.TrimSpace(os.Getenv("AMIN_XRAY_CONFIG"))
	if path == "" {
		path = "/usr/local/etc/xray/config.json"
	}
	bin := strings.TrimSpace(os.Getenv("AMIN_XRAY_BINARY"))
	if bin == "" {
		bin = "/usr/local/bin/xray"
	}
	service := strings.TrimSpace(os.Getenv("AMIN_XRAY_SERVICE"))
	if service == "" {
		service = "xray"
	}
	if !filepath.IsAbs(path) || !filepath.IsAbs(bin) {
		return nil, errors.New("Xray config and binary paths must be absolute")
	}
	if !serviceNamePattern.MatchString(service) {
		return nil, errors.New("invalid Xray systemd service name")
	}
	return &ConfigManager{Path: filepath.Clean(path), XrayBinary: filepath.Clean(bin), Service: service}, nil
}

func (m *ConfigManager) read() (map[string]interface{}, error) {
	b, err := os.ReadFile(m.Path)
	if err != nil {
		return nil, err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("invalid Xray JSON: %w", err)
	}
	if cfg == nil {
		return nil, errors.New("Xray config must be a JSON object")
	}
	return cfg, nil
}

func inboundList(cfg map[string]interface{}) ([]interface{}, error) {
	raw, ok := cfg["inbounds"]
	if !ok {
		return []interface{}{}, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, errors.New("Xray inbounds must be an array")
	}
	return list, nil
}

func stringField(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}

func (m *ConfigManager) validateAndApply(cfg map[string]interface{}) error {
	dir := filepath.Dir(m.Path)
	tmp, err := os.CreateTemp(dir, ".amin-xray-validate-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
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
	cmd := exec.Command(m.XrayBinary, "run", "-test", "-config", tmpPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Xray rejected config: %s", strings.TrimSpace(string(out)))
	}

	original, err := os.ReadFile(m.Path)
	if err != nil {
		return err
	}
	backup := m.Path + ".amin-backup-" + time.Now().UTC().Format("20060102T150405.000000000")
	if err := os.WriteFile(backup, original, 0600); err != nil {
		return fmt.Errorf("create config backup: %w", err)
	}
	newFile, err := os.CreateTemp(dir, ".amin-xray-live-*.json")
	if err != nil {
		return err
	}
	newPath := newFile.Name()
	defer os.Remove(newPath)
	if _, err := newFile.Write(bytes.TrimSpace(mustJSON(cfg))); err != nil {
		newFile.Close()
		return err
	}
	if err := newFile.Sync(); err != nil {
		newFile.Close()
		return err
	}
	if err := newFile.Close(); err != nil {
		return err
	}
	if err := os.Chmod(newPath, 0600); err != nil {
		return err
	}
	if err := os.Rename(newPath, m.Path); err != nil {
		return err
	}
	restart := exec.Command("systemctl", "restart", m.Service)
	if out, err := restart.CombinedOutput(); err != nil {
		_ = os.WriteFile(m.Path+".rollback", original, 0600)
		_ = os.Rename(m.Path+".rollback", m.Path)
		rollback := exec.Command("systemctl", "restart", m.Service)
		_, _ = rollback.CombinedOutput()
		return fmt.Errorf("Xray restart failed; previous config restored: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func mustJSON(v interface{}) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

func (m *ConfigManager) ListInbounds() ([]map[string]interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, err := m.read()
	if err != nil {
		return nil, err
	}
	raw, err := inboundList(cfg)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		in, ok := item.(map[string]interface{})
		if !ok {
			return nil, errors.New("invalid inbound entry")
		}
		out = append(out, in)
	}
	return out, nil
}

func (m *ConfigManager) AddInbound(in Inbound) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`).MatchString(in.Tag) {
		return errors.New("tag must contain 1-64 letters, digits, dot, underscore or dash")
	}
	if in.Port < 1 || in.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	switch in.Protocol {
	case "vless", "vmess", "trojan", "shadowsocks":
	default:
		return errors.New("unsupported protocol")
	}
	if in.Settings == nil {
		return errors.New("settings is required")
	}
	cfg, err := m.read()
	if err != nil {
		return err
	}
	list, err := inboundList(cfg)
	if err != nil {
		return err
	}
	for _, item := range list {
		existing, ok := item.(map[string]interface{})
		if !ok {
			return errors.New("invalid inbound entry")
		}
		if stringField(existing, "tag") == in.Tag {
			return errors.New("inbound tag already exists")
		}
		if port, ok := existing["port"].(float64); ok && int(port) == in.Port {
			return errors.New("inbound port already exists")
		}
	}
	obj := map[string]interface{}{"tag": in.Tag, "port": in.Port, "protocol": in.Protocol, "settings": in.Settings}
	if in.Listen != "" {
		obj["listen"] = in.Listen
	}
	if in.StreamSettings != nil {
		obj["streamSettings"] = in.StreamSettings
	}
	if in.Sniffing != nil {
		obj["sniffing"] = in.Sniffing
	}
	cfg["inbounds"] = append(list, obj)
	return m.validateAndApply(cfg)
}

func (m *ConfigManager) DeleteInbound(tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`).MatchString(tag) {
		return errors.New("invalid inbound tag")
	}
	cfg, err := m.read()
	if err != nil {
		return err
	}
	list, err := inboundList(cfg)
	if err != nil {
		return err
	}
	next := make([]interface{}, 0, len(list))
	found := false
	for _, item := range list {
		in, ok := item.(map[string]interface{})
		if !ok {
			return errors.New("invalid inbound entry")
		}
		if stringField(in, "tag") == tag {
			found = true
			continue
		}
		next = append(next, item)
	}
	if !found {
		return os.ErrNotExist
	}
	cfg["inbounds"] = next
	return m.validateAndApply(cfg)
}

func (m *ConfigManager) mutateClients(tag string, mutate func([]interface{}) ([]interface{}, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, err := m.read()
	if err != nil {
		return err
	}
	list, err := inboundList(cfg)
	if err != nil {
		return err
	}
	found := false
	for _, item := range list {
		in, ok := item.(map[string]interface{})
		if !ok {
			return errors.New("invalid inbound entry")
		}
		if stringField(in, "tag") != tag {
			continue
		}
		found = true
		protocol := stringField(in, "protocol")
		switch protocol {
		case "vless", "vmess":
			if stringField(client, "id") == "" {
				return errors.New("client id (UUID) is required for vless/vmess")
			}
		case "trojan":
			if stringField(client, "password") == "" {
				return errors.New("client password is required for trojan")
			}
		case "shadowsocks":
			if stringField(client, "password") == "" || stringField(client, "method") == "" {
				return errors.New("client password and method are required for shadowsocks")
			}
		default:
			return errors.New("unsupported inbound protocol for client management")
		}
		settings, ok := in["settings"].(map[string]interface{})
		if !ok {
			return errors.New("inbound settings are invalid")
		}
		var clients []interface{}
		if raw, exists := settings["clients"]; exists {
			clients, ok = raw.([]interface{})
			if !ok {
				return errors.New("inbound clients must be an array")
			}
		}
		updated, err := mutate(clients)
		if err != nil {
			return err
		}
		settings["clients"] = updated
	}
	if !found {
		return os.ErrNotExist
	}
	return m.validateAndApply(cfg)
}

func (m *ConfigManager) AddClient(tag string, client map[string]interface{}) error {
	allowed := map[string]bool{"email": true, "id": true, "level": true, "flow": true, "alterId": true, "security": true, "password": true, "method": true}
	for key := range client {
		if !allowed[key] {
			return fmt.Errorf("unsupported client field: %s", key)
		}
	}
	email := stringField(client, "email")
	if email == "" || len(email) > 128 || strings.ContainsAny(email, "\r\n") {
		return errors.New("client email is required and must be valid")
	}
	if len(client) == 0 {
		return errors.New("client fields are required")
	}
	return m.mutateClients(tag, func(clients []interface{}) ([]interface{}, error) {
		for _, raw := range clients {
			existing, ok := raw.(map[string]interface{})
			if !ok {
				return nil, errors.New("invalid client entry")
			}
			if stringField(existing, "email") == email {
				return nil, errors.New("client email already exists")
			}
		}
		return append(clients, client), nil
	})
}

func (m *ConfigManager) DeleteClient(tag, email string) error {
	if email == "" || len(email) > 128 || strings.ContainsAny(email, "\r\n") {
		return errors.New("invalid client email")
	}
	return m.mutateClients(tag, func(clients []interface{}) ([]interface{}, error) {
		next := make([]interface{}, 0, len(clients))
		found := false
		for _, raw := range clients {
			client, ok := raw.(map[string]interface{})
			if !ok {
				return nil, errors.New("invalid client entry")
			}
			if stringField(client, "email") == email {
				found = true
				continue
			}
			next = append(next, raw)
		}
		if !found {
			return nil, os.ErrNotExist
		}
		return next, nil
	})
}
