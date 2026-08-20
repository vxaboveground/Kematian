//go:build linux

package browser

import (
	"os"
	"path/filepath"
	"strings"

	"recovery/recovery/types"
)

var Browsers = []types.BrowserConfig{
	// Chromium family
	{Name: "Chrome", UserDataPath: "google-chrome", ProcessName: "chrome"},
	{Name: "Chrome Beta", UserDataPath: "google-chrome-beta", ProcessName: "chrome"},
	{Name: "Chrome Dev", UserDataPath: "google-chrome-unstable", ProcessName: "chrome"},
	{Name: "Chromium", UserDataPath: "chromium", ProcessName: "chromium"},
	{Name: "Edge", UserDataPath: "microsoft-edge", ProcessName: "msedge"},
	{Name: "Brave", UserDataPath: "BraveSoftware/Brave-Browser", ProcessName: "brave"},
	{Name: "Vivaldi", UserDataPath: "vivaldi", ProcessName: "vivaldi"},
	{Name: "Opera", UserDataPath: "opera", ProcessName: "opera", FlatProfile: true},
	// Firefox family
	{Name: "Firefox", UserDataPath: ".mozilla/firefox", ProcessName: "firefox", IsFirefox: true},
	{Name: "LibreWolf", UserDataPath: ".librewolf", ProcessName: "librewolf", IsFirefox: true},
	{Name: "Waterfox", UserDataPath: ".waterfox", ProcessName: "waterfox", IsFirefox: true},
}

func GetLocalAppData() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config")
}

func GetUserDataRoot(cfg types.BrowserConfig) string {
	if cfg.IsFirefox {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, cfg.UserDataPath)
	}
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
	profilesDir := root
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
