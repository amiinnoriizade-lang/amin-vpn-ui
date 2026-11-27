package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// UserTraffic contains Xray's cumulative per-user traffic counters.
type UserTraffic struct {
	Email string `json:"email"`
	Up    int64  `json:"up"`
	Down  int64  `json:"down"`
	Online bool `json:"online"`
}

type statsQueryResponse struct {
	Stat []struct {
		Name  string `json:"name"`
		Value json.Number `json:"value"`
	} `json:"stat"`
}

// StatsAPIAddress returns the loopback API listener only when StatsService is
// explicitly enabled in the existing Xray configuration. The Agent never
// rewrites Xray settings just to turn statistics on.
func (m *ConfigManager) StatsAPIAddress() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg, err := m.read()
	if err != nil {
		return "", err
	}
	api, ok := cfg["api"].(map[string]interface{})
	if !ok {
		return "", errors.New("Xray StatsService is not configured")
	}
	tag := stringField(api, "tag")
	services, _ := api["services"].([]interface{})
	hasStats := false
	for _, raw := range services {
		if service, ok := raw.(string); ok && service == "StatsService" {
			hasStats = true
			break
		}
	}
	if !hasStats {
		return "", errors.New("Xray StatsService is not enabled")
	}
	inbounds, err := inboundList(cfg)
	if err != nil {
		return "", err
	}
	for _, raw := range inbounds {
		inbound, ok := raw.(map[string]interface{})
		if !ok || stringField(inbound, "tag") != tag || tag == "" {
			continue
		}
		portValue, ok := inbound["port"].(float64)
		if !ok || portValue < 1 || portValue > 65535 || portValue != float64(int(portValue)) {
			return "", errors.New("Xray API inbound has an invalid port")
		}
		host := stringField(inbound, "listen")
		if host == "" {
			host = "127.0.0.1"
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", errors.New("Xray API inbound must listen on a loopback address")
		}
		return net.JoinHostPort(host, strconv.Itoa(int(portValue))), nil
	}
	return "", errors.New("Xray API inbound referenced by api.tag was not found")
}

// QueryUserTraffic reads cumulative Xray user counters without resetting them.
// This lets the panel calculate per-user rates from consecutive safe samples.
func (m *ConfigManager) QueryUserTraffic(ctx context.Context) ([]UserTraffic, error) {
	server, err := m.StatsAPIAddress()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, m.XrayBinary, "api", "statsquery", "--server="+server, "-pattern", "user>>>", "-reset=false")
	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("query Xray traffic stats: %w", ctx.Err())
		}
		return nil, fmt.Errorf("query Xray traffic stats: %w", err)
	}
	var response statsQueryResponse
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	decoder.UseNumber()
	if err := decoder.Decode(&response); err != nil {
		return nil, fmt.Errorf("decode Xray traffic stats: %w", err)
	}
	byEmail := make(map[string]*UserTraffic)
	for _, stat := range response.Stat {
		parts := strings.Split(stat.Name, ">>>")
		if len(parts) < 3 || parts[0] != "user" || parts[1] == "" {
			continue
		}
		item := byEmail[strings.ToLower(parts[1])]
		if item == nil {
			item = &UserTraffic{Email: strings.ToLower(parts[1])}
			byEmail[item.Email] = item
		}
		value, err := strconv.ParseInt(stat.Value.String(), 10, 64)
		if err != nil || value < 0 {
			return nil, fmt.Errorf("Xray returned an invalid traffic counter for %q", stat.Name)
		}
		if len(parts) == 3 && parts[2] == "online" {
			item.Online = value > 0
			continue
		}
		if len(parts) != 4 || parts[2] != "traffic" {
			continue
		}
		switch parts[3] {
		case "uplink":
			item.Up = value
		case "downlink":
			item.Down = value
		}
	}
	result := make([]UserTraffic, 0, len(byEmail))
	for _, item := range byEmail {
		result = append(result, *item)
	}
	return result, nil
}
