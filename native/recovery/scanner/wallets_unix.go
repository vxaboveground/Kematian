//go:build !windows

package scanner

import (
	"os"
	"path/filepath"
	"runtime"
)

func getDesktopWalletPaths() []walletConfig {
	if runtime.GOOS == "darwin" {
		return []walletConfig{
			{"Atomic", "atomic/Local Storage/leveldb", "appdata"},
			{"Exodus", "Exodus/exodus.wallet", "appdata"},
			{"Electrum", "Electrum/wallets", "home_dot"},
			{"Ethereum", "Ethereum/keystore", "home_dot"},
			{"Coinomi", "Coinomi/wallets", "appdata"},
		}
	}
	// Linux
	return []walletConfig{
		{"Atomic", "atomic/Local Storage/leveldb", "config"},
		{"Exodus", "Exodus/exodus.wallet", "config"},
		{"Electrum", ".electrum/wallets", "home"},
		{"Electrum-LTC", ".electrum-ltc/wallets", "home"},
		{"Ethereum", ".ethereum/keystore", "home"},
		{"Monero", "Monero/wallets", "home"},
		{"Armory", ".armory", "home"},
		{"Bytecoin", ".bytecoin", "home"},
		{"Coinomi", ".coinomi/Coinomi/wallets", "home"},
	}
}

func resolveWalletBase(base string) string {
	home, _ := os.UserHomeDir()
	switch base {
	case "home", "userprofile":
		return home
	case "home_dot":
		return filepath.Join(home, ".")
	case "appdata":
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "Application Support")
		}
		return filepath.Join(home, ".config")
	case "config":
		xdg := os.Getenv("XDG_CONFIG_HOME")
		if xdg != "" {
			return xdg
		}
		return filepath.Join(home, ".config")
	case "localappdata":
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "Application Support")
		}
		return filepath.Join(home, ".local", "share")
	}
	return ""
}
