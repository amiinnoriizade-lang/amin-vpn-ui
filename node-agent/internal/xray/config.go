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
	"syscall"
	"time"
)

var serviceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.@-]{1,128}$`)
var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

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

	originalInfo, err := os.Stat(m.Path)
	if err != nil {
		return err
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
	if err := preserveFileMetadata(newPath, originalInfo); err != nil {
		return fmt.Errorf("preserve Xray config ownership and permissions: %w", err)
	}
	if err := os.Rename(newPath, m.Path); err != nil {
		return err
	}
	restart := exec.Command("systemctl", "restart", m.Service)
	if out, err := restart.CombinedOutput(); err != nil {
		rollbackPath := m.Path + ".rollback"
		if writeErr := os.WriteFile(rollbackPath, original, 0600); writeErr == nil {
			if metaErr := preserveFileMetadata(rollbackPath, originalInfo); metaErr == nil {
				_ = os.Rename(rollbackPath, m.Path)
			} else {
				_ = os.Remove(rollbackPath)
			}
		}
		rollback := exec.Command("systemctl", "restart", m.Service)
		_, _ = rollback.CombinedOutput()
		return fmt.Errorf("Xray restart failed; previous config restored: %s", strings.TrimSpace(string(out)))
	}
	return nil
}


// preserveFileMetadata applies the existing config's owner, group, and permission
// bits to an atomically staged replacement before it becomes the live file.
func preserveFileMetadata(path string, original os.FileInfo) error {
	stat, ok := original.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("unsupported config file metadata")
	}
	current, err := os.Stat(path)
	if err != nil {
		return err
	}
	currentStat, ok := current.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("unsupported staged file metadata")
	}
	if currentStat.Uid != stat.Uid || currentStat.Gid != stat.Gid {
		if err := os.Chown(path, int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}
	}
	// Chown may clear special bits, so apply permissions after ownership.
	return os.Chmod(path, original.Mode().Perm())
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

func (m *ConfigManager) mutateClients(tag string, mutate func(string, []interface{}) ([]interface{}, error)) error {
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
		updated, err := mutate(protocol, clients)
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
	allowed := map[string]bool{"email": true, "id": true, "level": true, "flow": true, "alterId": true, "security": true, "password": true}
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
	for _, key := range []string{"email", "id", "flow", "security", "password"} {
		if value, exists := client[key]; exists {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("client field %s must be a string", key)
			}
		}
	}
	for _, key := range []string{"level", "alterId"} {
		if value, exists := client[key]; exists {
			if _, ok := value.(float64); !ok {
				return fmt.Errorf("client field %s must be a number", key)
			}
		}
	}
	if strings.TrimSpace(email) != email || strings.ContainsAny(email, " \t\r\n") {
		return errors.New("client email must not contain whitespace")
	}
	return m.mutateClients(tag, func(protocol string, clients []interface{}) ([]interface{}, error) {
		credentialKey := ""
		switch protocol {
		case "vless", "vmess":
			id := stringField(client, "id")
			if !uuidPattern.MatchString(id) {
				return nil, errors.New("client id must be a valid UUID for vless/vmess")
			}
			credentialKey = "id"
		case "trojan", "shadowsocks":
			if stringField(client, "password") == "" {
				return nil, fmt.Errorf("client password is required for %s", protocol)
			}
			credentialKey = "password"
		default:
			return nil, errors.New("unsupported inbound protocol for client management")
		}
		for _, raw := range clients {
			existing, ok := raw.(map[string]interface{})
			if !ok {
				return nil, errors.New("invalid client entry")
			}
			if stringField(existing, "email") == email {
				return nil, errors.New("client email already exists")
			}
			if stringField(existing, credentialKey) == stringField(client, credentialKey) {
				return nil, fmt.Errorf("client %s already exists", credentialKey)
			}
		}
		return append(clients, client), nil
	})
}

// UpdateClient applies a restricted patch to one existing Xray client while
// preserving all credentials and settings not explicitly changed by the caller.
func (m *ConfigManager) UpdateClient(tag, email string, patch map[string]interface{}) error {
	if email == "" || len(email) > 128 || strings.ContainsAny(email, "\\r\\n") {
		return errors.New("invalid client email")
	}
	allowed := map[string]bool{"id": true, "password": true, "flow": true, "level": true, "alterId": true, "security": true}
	if len(patch) == 0 {
		return errors.New("at least one client field must be updated")
	}
	for key, value := range patch {
		if !allowed[key] {
			return fmt.Errorf("unsupported client update field: %s", key)
		}
		switch key {
		case "id", "password", "flow", "security":
			if _, ok := value.(string); !ok {
				return fmt.Errorf("client field %s must be a string", key)
			}
		case "level", "alterId":
			if _, ok := value.(float64); !ok {
				return fmt.Errorf("client field %s must be a number", key)
			}
		}
	}
	return m.mutateClients(tag, func(protocol string, clients []interface{}) ([]interface{}, error) {
		next := make([]interface{}, len(clients))
		copy(next, clients)
		found := false
		for i, raw := range next {
			client, ok := raw.(map[string]interface{})
			if !ok {
				return nil, errors.New("invalid client entry")
			}
			if !strings.EqualFold(stringField(client, "email"), email) {
				continue
			}
			found = true
			updated := make(map[string]interface{}, len(client)+len(patch))
			for key, value := range client { updated[key] = value }
			for key, value := range patch { updated[key] = value }
			credentialKey := ""
			switch protocol {
			case "vless", "vmess":
				if !uuidPattern.MatchString(stringField(updated, "id")) {
					return nil, errors.New("client id must be a valid UUID for vless/vmess")
				}
				if _, exists := updated["password"]; exists {
					return nil, errors.New("password is not valid for vless/vmess clients")
				}
				credentialKey = "id"
			case "trojan", "shadowsocks":
				if stringField(updated, "password") == "" {
					return nil, fmt.Errorf("client password is required for %s", protocol)
				}
				if _, exists := updated["id"]; exists {
					return nil, fmt.Errorf("id is not valid for %s clients", protocol)
				}
				credentialKey = "password"
			default:
				return nil, errors.New("unsupported inbound protocol for client management")
			}
			for j, otherRaw := range next {
				if j == i { continue }
				other, ok := otherRaw.(map[string]interface{})
				if !ok { return nil, errors.New("invalid client entry") }
				if stringField(other, credentialKey) == stringField(updated, credentialKey) {
					return nil, fmt.Errorf("client %s already exists", credentialKey)
				}
			}
			next[i] = updated
			break
		}
		if !found {
			return nil, os.ErrNotExist
		}
		return next, nil
	})
}

func (m *ConfigManager) DeleteClient(tag, email string) error {
	if email == "" || len(email) > 128 || strings.ContainsAny(email, "\r\n") {
		return errors.New("invalid client email")
	}
	return m.mutateClients(tag, func(_ string, clients []interface{}) ([]interface{}, error) {
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
