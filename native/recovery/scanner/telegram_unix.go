//go:build !windows

package scanner

import (
	"os"
	"path/filepath"
	"runtime"
)

func getTelegramPaths() []telegramPathConfig {
	if runtime.GOOS == "darwin" {
		return []telegramPathConfig{
			{"Telegram Desktop", "Telegram Desktop/tdata", "appdata"},
			{"Kotatogram", "Kotatogram Desktop/tdata", "appdata"},
			{"64Gram", "64Gram Desktop/tdata", "appdata"},
		}
	}
	// Linux
	return []telegramPathConfig{
		{"Telegram Desktop", "TelegramDesktop/tdata", "home_data"},
		{"Telegram Desktop (flatpak)", ".var/app/org.telegram.desktop/data/TelegramDesktop/tdata", "home"},
		{"Telegram Desktop (snap)", "snap/telegram-desktop/current/.local/share/TelegramDesktop/tdata", "home"},
		{"Kotatogram", "KotatogramDesktop/tdata", "home_data"},
		{"64Gram", "64Gram Desktop/tdata", "home_data"},
	}
}

func resolveTelegramBase(base string) string {
	home, _ := os.UserHomeDir()
	switch base {
	case "home":
		return home
	case "home_data":
		xdg := os.Getenv("XDG_DATA_HOME")
		if xdg != "" {
			return xdg
		}
		return filepath.Join(home, ".local", "share")
	case "appdata":
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "Application Support")
		}
		return filepath.Join(home, ".config")
	case "localappdata":
		return filepath.Join(home, ".local", "share")
	case "userprofile":
		return home
	}
	return ""
}
