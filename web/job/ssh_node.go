package job

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHNodeConfig is the panel-side credential set for a remote Xray node.
// PrivateKey must be decrypted by the caller and must never be logged.
type SSHNodeConfig struct {
	Address       string
	Port          int
	Username      string
	PrivateKey    []byte
	KnownHosts    string
	Timeout       time.Duration
}

// DialSSHNode establishes an authenticated SSH connection with strict host-key
// verification. Callers must close the returned client. It is also used for
// forwarding the node's loopback-only Xray gRPC API through SSH.
func DialSSHNode(cfg SSHNodeConfig) (*ssh.Client, error) {
	host := strings.TrimSpace(cfg.Address)
	if host == "" || strings.ContainsAny(host, "/?#@") { return nil, fmt.Errorf("invalid SSH node address") }
	if cfg.Port < 1 || cfg.Port > 65535 { return nil, fmt.Errorf("invalid SSH port") }
	if strings.TrimSpace(cfg.Username) == "" || len(cfg.PrivateKey) == 0 { return nil, fmt.Errorf("SSH username and private key are required") }
	if cfg.KnownHosts == "" { cfg.KnownHosts = SSHKnownHostsPath() }
	if cfg.Timeout <= 0 { cfg.Timeout = 12 * time.Second }
	signer, err := ssh.ParsePrivateKey(cfg.PrivateKey)
	if err != nil { return nil, fmt.Errorf("parse SSH private key: %w", err) }
	hostKeyCallback, err := knownhosts.New(cfg.KnownHosts)
	if err != nil { return nil, fmt.Errorf("load SSH known_hosts: %w", err) }
	address := net.JoinHostPort(host, fmt.Sprint(cfg.Port))
	conn, err := net.DialTimeout("tcp", address, cfg.Timeout)
	if err != nil { return nil, fmt.Errorf("connect to SSH node: %w", err) }
	_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, address, &ssh.ClientConfig{
		User: cfg.Username, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback, Timeout: cfg.Timeout,
	})
	if err != nil { _ = conn.Close(); return nil, fmt.Errorf("authenticate SSH node: %w", err) }
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(clientConn, chans, reqs), nil
}

// RunSSHNodeCommand executes a panel-authored command on a remote node.
// Host keys are verified against the configured known_hosts file; insecure
// host-key bypasses are deliberately not supported.
func RunSSHNodeCommand(cfg SSHNodeConfig, command string) ([]byte, error) {
	host := strings.TrimSpace(cfg.Address)
	if host == "" || strings.ContainsAny(host, "/?#@") {
		return nil, fmt.Errorf("invalid SSH node address")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("invalid SSH port")
	}
	if strings.TrimSpace(cfg.Username) == "" || len(cfg.PrivateKey) == 0 {
		return nil, fmt.Errorf("SSH username and private key are required")
	}
	if strings.TrimSpace(command) == "" {
		return nil, fmt.Errorf("SSH command is empty")
	}
	if cfg.KnownHosts == "" {
		cfg.KnownHosts = "/etc/amin-ui/known_hosts"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 12 * time.Second
	}

	signer, err := ssh.ParsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse SSH private key: %w", err)
	}
	hostKeyCallback, err := knownhosts.New(cfg.KnownHosts)
	if err != nil {
		return nil, fmt.Errorf("load SSH known_hosts: %w", err)
	}

	clientConfig := &ssh.ClientConfig{
		User: cfg.Username,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout: cfg.Timeout,
	}
	address := net.JoinHostPort(host, fmt.Sprint(cfg.Port))
	conn, err := net.DialTimeout("tcp", address, cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to SSH node: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, address, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("authenticate SSH node: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	if err := session.Run(command); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return stdout.Bytes(), fmt.Errorf("remote command failed: %w: %s", err, detail)
		}
		return stdout.Bytes(), fmt.Errorf("remote command failed: %w", err)
	}
	return stdout.Bytes(), nil
}

// RunSSHNodeCommandInput runs a fixed command and streams caller-supplied data to stdin.
func RunSSHNodeCommandInput(cfg SSHNodeConfig, command string, input []byte) ([]byte,error) {
 client,err:=DialSSHNode(cfg)
 if err!=nil { return nil,err }
 defer client.Close()
 session,err:=client.NewSession()
 if err!=nil { return nil,fmt.Errorf("open SSH session: %w",err) }
 defer session.Close()
 var stdout,stderr bytes.Buffer
 session.Stdout=&stdout
 session.Stderr=&stderr
 stdin,err:=session.StdinPipe()
 if err!=nil { return nil,err }
 if err=session.Start(command);err!=nil { return nil,err }
 if _,err=stdin.Write(input);err!=nil { _=stdin.Close(); return nil,err }
 _=stdin.Close()
 if err=session.Wait();err!=nil {
  detail:=strings.TrimSpace(stderr.String())
  if detail!="" { return stdout.Bytes(),fmt.Errorf("remote command failed: %w: %s",err,detail) }
  return stdout.Bytes(),fmt.Errorf("remote command failed: %w",err)
 }
 return stdout.Bytes(),nil
}

// Ensure the default known_hosts location can be provisioned by the installer.
func SSHKnownHostsPath() string { return "/etc/amin-ui/known_hosts" }

// SSHPrivateKeyFilePermissions returns true only for a regular, owner-only key file.
func SSHPrivateKeyFilePermissions(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	return info.Mode().Perm()&0077 == 0
}
