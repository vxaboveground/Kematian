//go:build windows

package scanner

import "os"

func getTelegramPaths() []telegramPathConfig {
	return []telegramPathConfig{
		{"Telegram Desktop", `Telegram Desktop\tdata`, "appdata"},
		{"Telegram Desktop (alt)", `Telegram Desktop\tdata`, "userprofile"},
		{"Kotatogram", `Kotatogram Desktop\tdata`, "appdata"},
		{"64Gram", `64Gram Desktop\tdata`, "appdata"},
		{"Unigram", `Unigram\$local\tdata`, "localappdata"},
	}
}

func resolveTelegramBase(base string) string {
	switch base {
	case "appdata":
		return os.Getenv("APPDATA")
	case "localappdata":
		return os.Getenv("LOCALAPPDATA")
	case "userprofile":
		return os.Getenv("USERPROFILE")
	}
	return ""
}
