//go:build !windows

package platform

import "os"

func ReadLockedFile(srcPath string, pids []uint32) ([]byte, error) {
	return os.ReadFile(srcPath)
}

func ResetHandleCache() {}
