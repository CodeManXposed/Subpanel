package token

import (
	"crypto/rand"
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

// Hash 直接返回原 token(不再哈希)。
// 设计原因:用户要求面板能直接看到 token 原文用于反查用户。
// salt 文件仍保留,留作未来如果要切回哈希用,也用于 HMAC 签名其他用途。
// 注意:DB 字段名仍叫 token_hash,但内容已是原文。
func (h *Hasher) Hash(token string) string {
	return token
}
