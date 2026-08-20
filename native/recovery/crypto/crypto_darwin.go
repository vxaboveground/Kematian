//go:build darwin

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"recovery/recovery/browser"
	"recovery/recovery/types"

	"golang.org/x/crypto/pbkdf2"
)

const (
	darwinChromeSalt       = "saltysalt"
	darwinChromeIterations = 1003
	darwinChromeKeyLen     = 16
)

var chromeKeychainServices = map[string]string{
	"Chrome":        "Chrome Safe Storage",
	"Chrome Beta":   "Chrome Safe Storage",
	"Chrome Canary": "Chrome Safe Storage",
	"Chromium":      "Chromium Safe Storage",
	"Edge":          "Microsoft Edge Safe Storage",
	"Brave":         "Brave Safe Storage",
	"Vivaldi":       "Vivaldi Safe Storage",
	"Opera":         "Opera Safe Storage",
	"Opera GX":      "Opera Safe Storage",
	"Arc":           "Arc Safe Storage",
	"Yandex":        "Yandex Safe Storage",
}

func getKeychainPassword(browserName string) (string, error) {
	service, ok := chromeKeychainServices[browserName]
	if !ok {
		service = browserName + " Safe Storage"
	}

	cmd := exec.Command("security", "find-generic-password", "-wa", service)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("keychain lookup failed for %s: %w", service, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func ResolveKeys(cfg types.BrowserConfig) (*types.ResolvedKeys, error) {
	if cfg.IsFirefox {
		return &types.ResolvedKeys{}, nil
	}

	localStatePath := browser.LocalStatePath(cfg)
	if _, err := os.Stat(localStatePath); err != nil {
		// fuck it we still trying
		return resolveKeyFromKeychain(cfg)
	}

	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return resolveKeyFromKeychain(cfg)
	}

	var localState map[string]interface{}
	if err := json.Unmarshal(data, &localState); err != nil {
		return resolveKeyFromKeychain(cfg)
	}

	return resolveKeyFromKeychain(cfg)
}

func resolveKeyFromKeychain(cfg types.BrowserConfig) (*types.ResolvedKeys, error) {
	password, err := getKeychainPassword(cfg.Name)
	if err != nil {
		return nil, fmt.Errorf("could not get keychain password for %s: %w", cfg.Name, err)
	}

	key := pbkdf2.Key([]byte(password), []byte(darwinChromeSalt), darwinChromeIterations, darwinChromeKeyLen, sha1.New)
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
	return nil, fmt.Errorf("DPAPI not available on macOS")
}
