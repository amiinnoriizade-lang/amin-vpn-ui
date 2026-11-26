// Package nodetoken encrypts remote node API tokens before they are stored in the panel database.
package nodetoken

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/config"
)

const prefix = "enc:v1:"

// keyFilePath returns a separate, permission-restricted key file. Keep this file
// with the panel's protected data and include it in encrypted backups.
func keyFilePath() string {
	if p := strings.TrimSpace(os.Getenv("VPNUI_NODE_TOKEN_KEY_FILE")); p != "" {
		return p
	}
	return filepath.Join(config.GetDBFolderPath(), "node-token.key")
}

func loadKey(create bool) ([]byte, error) {
	path := keyFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create node token key directory: %w", err)
	}
	if create {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, fmt.Errorf("generate node token key: %w", err)
		}
		tmp, err := os.CreateTemp(filepath.Dir(path), ".node-token-key-*")
		if err != nil {
			return nil, fmt.Errorf("stage node token key: %w", err)
		}
		tmpPath := tmp.Name()
		defer os.Remove(tmpPath)
		if err = tmp.Chmod(0600); err == nil {
			_, err = tmp.Write(key)
		}
		if err == nil {
			err = tmp.Sync()
		}
		if closeErr := tmp.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return nil, fmt.Errorf("write node token key: %w", err)
		}
		// Link is atomic and never overwrites a key another process created.
		if err = os.Link(tmpPath, path); err == nil {
			return key, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("install node token key: %w", err)
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("node token key is missing; restore node-token.key from backup or re-enter the node token")
		}
		return nil, fmt.Errorf("inspect node token key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("node token key must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("node token key permissions are too broad; set the key file mode to 0600")
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read node token key: %w", err)
	}
	if len(key) != 32 {
		return nil, errors.New("node token key must contain exactly 32 bytes")
	}
	return key, nil
}

// Encrypt returns an authenticated AES-256-GCM ciphertext. Existing ciphertext
// is validated and returned unchanged; legacy plaintext remains readable.
func Encrypt(token string) (string, error) {
	if token == "" {
		return "", errors.New("node API token is empty")
	}
	if strings.HasPrefix(token, prefix) {
		if _, err := Decrypt(token); err != nil {
			return "", err
		}
		return token, nil
	}
	key, err := loadKey(true)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(token), nil)
	return prefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Decrypt transparently supports legacy plaintext rows so upgrades do not
// invalidate existing node registrations.
func Decrypt(token string) (string, error) {
	if !strings.HasPrefix(token, prefix) {
		return token, nil
	}
	key, err := loadKey(false)
	if err != nil {
		return "", err
	}
	encoded := strings.TrimPrefix(token, prefix)
	sealed, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", errors.New("stored node API token has invalid ciphertext encoding")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return "", errors.New("stored node API token ciphertext is truncated")
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("could not decrypt stored node API token; restore node-token.key from backup or re-enter the token")
	}
	return string(plain), nil
}
