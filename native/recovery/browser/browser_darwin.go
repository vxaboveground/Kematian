//go:build darwin

package browser

import (
	"os"
	"path/filepath"
	"strings"

	"recovery/recovery/types"
)

var Browsers = []types.BrowserConfig{
	// Chromium family
	{Name: "Chrome", UserDataPath: "Google/Chrome", ProcessName: "Google Chrome"},
	{Name: "Chrome Beta", UserDataPath: "Google/Chrome Beta", ProcessName: "Google Chrome Beta"},
	{Name: "Chrome Canary", UserDataPath: "Google/Chrome Canary", ProcessName: "Google Chrome Canary"},
	{Name: "Chromium", UserDataPath: "Chromium", ProcessName: "Chromium"},
	{Name: "Edge", UserDataPath: "Microsoft Edge", ProcessName: "Microsoft Edge"},
	{Name: "Brave", UserDataPath: "BraveSoftware/Brave-Browser", ProcessName: "Brave Browser"},
	{Name: "Vivaldi", UserDataPath: "Vivaldi", ProcessName: "Vivaldi"},
	{Name: "Opera", UserDataPath: "com.operasoftware.Opera", ProcessName: "Opera", FlatProfile: true},
	{Name: "Opera GX", UserDataPath: "com.operasoftware.OperaGX", ProcessName: "Opera GX", FlatProfile: true},
	{Name: "Arc", UserDataPath: "Arc/User Data", ProcessName: "Arc"},
	{Name: "Yandex", UserDataPath: "Yandex/YandexBrowser", ProcessName: "Yandex"},
	// Firefox family
	{Name: "Firefox", UserDataPath: "Firefox", ProcessName: "firefox", IsFirefox: true},
	{Name: "LibreWolf", UserDataPath: "LibreWolf", ProcessName: "librewolf", IsFirefox: true},
	{Name: "Waterfox", UserDataPath: "Waterfox", ProcessName: "waterfox", IsFirefox: true},
}

func GetLocalAppData() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support")
}

func GetUserDataRoot(cfg types.BrowserConfig) string {
	return filepath.Join(GetLocalAppData(), cfg.UserDataPath)
}

func LocalStatePath(cfg types.BrowserConfig) string {
	return filepath.Join(GetUserDataRoot(cfg), "Local State")
}

func FindProfileDirs(cfg types.BrowserConfig) []types.ProfileInfo {
	root := GetUserDataRoot(cfg)

	if cfg.FlatProfile {
		if _, err := os.Stat(root); err == nil {
			return []types.ProfileInfo{{Name: "Default", Path: root}}
		}
		return nil
	}

	if cfg.IsFirefox {
		return findFirefoxProfiles(root)
	}

	return findChromiumProfiles(root)
}

func findChromiumProfiles(root string) []types.ProfileInfo {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var profiles []types.ProfileInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		prefPath := filepath.Join(root, e.Name(), "Preferences")
		if _, err := os.Stat(prefPath); err == nil {
			profiles = append(profiles, types.ProfileInfo{
				Name: e.Name(),
				Path: filepath.Join(root, e.Name()),
			})
		}
	}
	return profiles
}

func findFirefoxProfiles(root string) []types.ProfileInfo {
	profilesDir := filepath.Join(root, "Profiles")
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return nil
	}
	var profiles []types.ProfileInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(profilesDir, e.Name(), "prefs.js")); err == nil {
			profiles = append(profiles, types.ProfileInfo{
				Name: e.Name(),
				Path: filepath.Join(profilesDir, e.Name()),
			})
		}
	}
	return profiles
}

func IsFirefoxProfileName(name string) bool {
	parts := strings.SplitN(name, ".", 2)
	if len(parts) != 2 {
		return false
	}
	suffix := strings.ToLower(parts[1])
	return strings.HasPrefix(suffix, "default") || strings.HasPrefix(suffix, "release")
}
