package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

const saltSize = 32

// Hasher 用 HMAC-SHA256(salt, token) 给 token 打码
type Hasher struct {
	salt []byte
}

// LoadOrCreateSalt 从文件加载 salt,不存在则生成新的(权限 600)
func LoadOrCreateSalt(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		decoded, derr := hex.DecodeString(strings.TrimSpace(string(b)))
		if derr == nil && len(decoded) >= 16 {
			return decoded, nil
		}
		// 文件存在但内容不合法 -> 报错,避免覆盖
		if derr != nil {
			return nil, fmt.Errorf("salt file %s exists but is not valid hex: %w", path, derr)
		}
		return nil, fmt.Errorf("salt file %s exists but is too short (need >= 16 bytes)", path)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	// 生成新的
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(salt)+"\n"), 0600); err != nil {
		return nil, err
	}
	return salt, nil
}

func NewHasher(salt []byte) *Hasher {
	cp := make([]byte, len(salt))
	copy(cp, salt)
	return &Hasher{salt: cp}
}

// Hash 返回十六进制小写,长度 64
func (h *Hasher) Hash(token string) string {
	if token == "" {
		return ""
	}
	mac := hmac.New(sha256.New, h.salt)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}
