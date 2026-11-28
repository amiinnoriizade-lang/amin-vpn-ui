package job

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// withSSHXrayAPI opens the Xray API, which must listen on the node's loopback
// interface, through the already host-key-verified SSH connection.
func withSSHXrayAPI(ctx context.Context, cfg SSHNodeConfig, fn func(command.HandlerServiceClient) error) error {
	sshClient, err := DialSSHNode(cfg)
	if err != nil { return err }
	defer sshClient.Close()

	dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, "passthrough:///amin-xray-api",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return sshClient.Dial("tcp", "127.0.0.1:10087")
		}),
		grpc.WithBlock(),
	)
	if err != nil { return fmt.Errorf("connect to Xray API through SSH: %w", err) }
	defer conn.Close()
	return fn(command.NewHandlerServiceClient(conn))
}

// SSHXrayAddVLESSClient adds a VLESS account to an existing live inbound.
// The caller is responsible for persisting the same account in config.json.
func SSHXrayAddVLESSClient(ctx context.Context, cfg SSHNodeConfig, tag, email, id, flow string) error {
	tag, email, id = strings.TrimSpace(tag), strings.TrimSpace(email), strings.TrimSpace(id)
	if tag == "" || email == "" || id == "" { return fmt.Errorf("inbound tag, email and client UUID are required") }
	if flow != "" && flow != "xtls-rprx-vision" { return fmt.Errorf("unsupported VLESS flow") }
	return withSSHXrayAPI(ctx, cfg, func(client command.HandlerServiceClient) error {
		user := &protocol.User{Level: 0, Email: email, Account: serial.ToTypedMessage(&vless.Account{Id: id, Flow: flow})}
		_, err := client.AlterInbound(ctx, &command.AlterInboundRequest{
			Tag: tag,
			Operation: serial.ToTypedMessage(&command.AddUserOperation{User: user}),
		})
		if err != nil { return fmt.Errorf("Xray rejected VLESS client: %w", err) }
		return nil
	})
}

// SSHXrayRemoveClient removes an account by its email from a live inbound.
func SSHXrayRemoveClient(ctx context.Context, cfg SSHNodeConfig, tag, email string) error {
	tag, email = strings.TrimSpace(tag), strings.TrimSpace(email)
	if tag == "" || email == "" { return fmt.Errorf("inbound tag and email are required") }
	return withSSHXrayAPI(ctx, cfg, func(client command.HandlerServiceClient) error {
		_, err := client.AlterInbound(ctx, &command.AlterInboundRequest{
			Tag: tag,
			Operation: serial.ToTypedMessage(&command.RemoveUserOperation{Email: email}),
		})
		if err != nil { return fmt.Errorf("Xray rejected client removal: %w", err) }
		return nil
	})
}
