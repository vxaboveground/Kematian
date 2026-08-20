//go:build !windows

package firefox

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned int type;
    unsigned char *data;
    unsigned int len;
} SECItem;

typedef int (*NSS_Init_Fn)(const char*);
typedef int (*NSS_Shutdown_Fn)(void);
typedef int (*PK11SDR_Decrypt_Fn)(SECItem*, SECItem*, void*);
typedef void (*PORT_Free_Fn)(void*);

static void* load_nss(const char* path) {
    return dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
}

static void close_nss(void* handle) {
    if (handle) dlclose(handle);
}

static int call_nss_init(void* handle, const char* profile) {
    NSS_Init_Fn fn = (NSS_Init_Fn)dlsym(handle, "NSS_Init");
    if (!fn) return -1;
    return fn(profile);
}

static int call_nss_shutdown(void* handle) {
    NSS_Shutdown_Fn fn = (NSS_Shutdown_Fn)dlsym(handle, "NSS_Shutdown");
    if (!fn) return -1;
    return fn();
}

static int call_pk11sdr_decrypt(void* handle, SECItem* enc, SECItem* dec) {
    PK11SDR_Decrypt_Fn fn = (PK11SDR_Decrypt_Fn)dlsym(handle, "PK11SDR_Decrypt");
    if (!fn) return -1;
    return fn(enc, dec, NULL);
}

static void call_port_free(void* handle, void* ptr) {
    PORT_Free_Fn fn = (PORT_Free_Fn)dlsym(handle, "PORT_Free");
    if (fn) fn(ptr);
}
*/
import "C"

import (
	"encoding/base64"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"recovery/recovery/types"
)

var nssLibPaths = []string{
	// Linux paths
	"/usr/lib/x86_64-linux-gnu/libnss3.so",
	"/usr/lib64/libnss3.so",
	"/usr/lib/libnss3.so",
	"/usr/lib/firefox/libnss3.so",
	"/usr/lib64/firefox/libnss3.so",
	"/opt/firefox/libnss3.so",
	"/opt/librewolf/libnss3.so",
	"/snap/firefox/current/usr/lib/firefox/libnss3.so",
	// macOS paths
	"/Applications/Firefox.app/Contents/MacOS/libnss3.dylib",
	"/Applications/LibreWolf.app/Contents/MacOS/libnss3.dylib",
	"/Applications/Waterfox.app/Contents/MacOS/libnss3.dylib",
	"/opt/homebrew/lib/libnss3.dylib",
	"/usr/local/lib/libnss3.dylib",
}

func findNSSLib() string {
	suffix := ".so"
	if runtime.GOOS == "darwin" {
		suffix = ".dylib"
	}
	for _, p := range nssLibPaths {
		if strings.HasSuffix(p, suffix) {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	name := "libnss3.so"
	if runtime.GOOS == "darwin" {
		name = "libnss3.dylib"
	}
	return name
}

func nssDecryptLogins(profilePath, browserName string, logins []firefoxLogin) []types.PasswordResult {
	libPath := findNSSLib()
	cLibPath := C.CString(libPath)
	defer C.free(unsafe.Pointer(cLibPath))

	handle := C.load_nss(cLibPath)
	if handle == nil {
		logf("firefox NSS: failed to load %s", libPath)
		return nil
	}
	defer C.close_nss(handle)

	cProfile := C.CString(profilePath)
	defer C.free(unsafe.Pointer(cProfile))

	ret := C.call_nss_init(handle, cProfile)
	if ret != 0 {
		logf("firefox NSS: NSS_Init failed for %s", profilePath)
		return nil
	}
	defer C.call_nss_shutdown(handle)

	var results []types.PasswordResult
	for _, login := range logins {
		username := nssDecryptUnix(handle, login.EncryptedUsername)
		password := nssDecryptUnix(handle, login.EncryptedPassword)
		results = append(results, types.PasswordResult{
			URL:      login.Hostname,
			Username: username,
			Password: password,
		})
	}

	return results
}

func nssDecryptUnix(handle unsafe.Pointer, b64 string) string {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return ""
	}

	encBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(encBytes) == 0 {
		return ""
	}

	var encItem C.SECItem
	encItem.data = (*C.uchar)(unsafe.Pointer(&encBytes[0]))
	encItem.len = C.uint(len(encBytes))

	var decItem C.SECItem
	ret := C.call_pk11sdr_decrypt(handle, &encItem, &decItem)
	if ret != 0 || decItem.data == nil || decItem.len == 0 {
		return ""
	}

	result := C.GoStringN((*C.char)(unsafe.Pointer(decItem.data)), C.int(decItem.len))
	C.call_port_free(handle, unsafe.Pointer(decItem.data))

	return result
}
