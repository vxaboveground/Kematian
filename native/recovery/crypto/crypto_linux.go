//go:build linux

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"

	"recovery/recovery/browser"
	"recovery/recovery/types"

	"golang.org/x/crypto/pbkdf2"
)

const (
	linuxChromePassword   = "peanuts"
	linuxChromeSalt       = "saltysalt"
	linuxChromeIterations = 1
	linuxChromeKeyLen     = 16
)

func ResolveKeys(cfg types.BrowserConfig) (*types.ResolvedKeys, error) {
	if cfg.IsFirefox {
		return &types.ResolvedKeys{}, nil
	}

	localStatePath := browser.LocalStatePath(cfg)
	if _, err := os.Stat(localStatePath); err != nil {
		key := pbkdf2.Key([]byte(linuxChromePassword), []byte(linuxChromeSalt), linuxChromeIterations, linuxChromeKeyLen, sha1.New)
		return &types.ResolvedKeys{V10: key}, nil
	}

	data, err := os.ReadFile(localStatePath)
	if err != nil {
		key := pbkdf2.Key([]byte(linuxChromePassword), []byte(linuxChromeSalt), linuxChromeIterations, linuxChromeKeyLen, sha1.New)
		return &types.ResolvedKeys{V10: key}, nil
	}

	var localState map[string]interface{}
	if err := json.Unmarshal(data, &localState); err != nil {
		key := pbkdf2.Key([]byte(linuxChromePassword), []byte(linuxChromeSalt), linuxChromeIterations, linuxChromeKeyLen, sha1.New)
		return &types.ResolvedKeys{V10: key}, nil
	}

	key := pbkdf2.Key([]byte(linuxChromePassword), []byte(linuxChromeSalt), linuxChromeIterations, linuxChromeKeyLen, sha1.New)
	return &types.ResolvedKeys{V10: key}, nil
}

func DecryptChromiumBlob(encrypted []byte, v10Key, v20Key []byte) string {
	if len(encrypted) == 0 {
		return ""
	}

	if len(encrypted) < 3 {
		return ""
	}
	prefix := string(encrypted[:3])
	if prefix != "v10" && prefix != "v11" {
		return ""
	}

	key := v10Key
	if key == nil || len(key) == 0 {
		return ""
	}

	ciphertext := encrypted[3:]
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return ""
	}

	plaintext, err := aesCBCDecrypt(key, ciphertext)
	if err != nil {
		return ""
	}
	return CleanPassword(plaintext)
}

func aesCBCDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = 0x20
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// PKCS5/PKCS7 unpad
	plaintext = pkcs5Unpad(plaintext)
	if plaintext == nil {
		return nil, fmt.Errorf("invalid padding")
	}
	return plaintext, nil
}

func pkcs5Unpad(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(data) {
		return nil
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil
		}
	}
	return data[:len(data)-padLen]
}

func CryptUnprotectData(in []byte) ([]byte, error) {
	return nil, fmt.Errorf("DPAPI not available on Linux")
}
