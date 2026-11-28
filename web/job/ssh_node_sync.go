package job

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/nodetoken"
)

// SSHNodeListInbounds reads the active Xray JSON configuration using a fixed,
// read-only command. No node-provided value is interpolated into the command.
func SSHNodeListInbounds(ctx context.Context, n model.Node) ([]NativeAgentInbound, error) {
	if !n.SSHMode { return nil, fmt.Errorf("node is not configured for direct SSH") }
	key, err := nodetoken.Decrypt(n.SSHPrivateKey)
	if err != nil { return nil, fmt.Errorf("decrypt SSH private key: %w", err) }
	port := n.SSHPort
	if port == 0 { port = 22 }
	type xrayConfig struct {
		Inbounds []struct {
			Tag string `json:"tag"`
			Port int `json:"port"`
			Listen string `json:"listen"`
			Protocol string `json:"protocol"`
			Settings json.RawMessage `json:"settings"`
			StreamSettings json.RawMessage `json:"streamSettings"`
		} `json:"inbounds"`
	}
	raw, err := RunSSHNodeCommand(SSHNodeConfig{
		Address:n.Address, Port:port, Username:n.SSHUsername,
		PrivateKey:[]byte(key), Timeout:12*time.Second,
	}, "cat /usr/local/etc/xray/config.json")
	if err != nil { return nil, fmt.Errorf("read Xray config over SSH: %w", err) }
	var config xrayConfig
	if err=json.Unmarshal(raw,&config); err!=nil { return nil, fmt.Errorf("decode Xray config: %w",err) }
	result:=make([]NativeAgentInbound,0,len(config.Inbounds))
	for _, ib:=range config.Inbounds {
		tag:=strings.TrimSpace(ib.Tag)
		if tag=="" || ib.Port<1 || ib.Port>65535 { continue }
		result=append(result,NativeAgentInbound{
			Tag:tag,Port:ib.Port,Listen:ib.Listen,Protocol:strings.ToLower(strings.TrimSpace(ib.Protocol)),
			Settings:ib.Settings,StreamSettings:ib.StreamSettings,
		})
	}
	return result,nil
}
