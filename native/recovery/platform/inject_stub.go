//go:build !windows

package platform

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

func InjectDLL(dllBytes []byte, pipeName string, targetPID uint32) (*PipeSession, error) {
	return nil, errors.New("DLL injection not supported on this platform")
}

func CreatePipeSession(dllBytes []byte, browserName string) (*PipeSession, error) {
	return nil, errors.New("pipe injection not supported on this platform")
}

func FindProcesses(exeName string) ([]uint32, error) {
	if exeName == "" {
		return nil, nil
	}
	out, err := exec.Command("pgrep", "-x", exeName).Output()
	if err != nil {
		return nil, nil
	}
	var pids []uint32
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if pid, err := strconv.ParseUint(line, 10, 32); err == nil {
			pids = append(pids, uint32(pid))
		}
	}
	return pids, nil
}

func BrowserExeName(name string) string {
	return ""
}

func TryV20KeyViaBrowserSession(processName, browserName string, encBlob []byte) ([]byte, error) {
	return nil, errors.New("not supported on this platform")
}
