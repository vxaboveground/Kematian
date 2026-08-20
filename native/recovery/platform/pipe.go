//go:build windows

package platform

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type PipeSession struct {
	mu          sync.Mutex
	hPipe       windows.Handle
	hProcess    windows.Handle
	pid         uint32
	ownsProcess bool
	closed      bool
}

var (
	modKernel32Pipe = windows.NewLazySystemDLL("kernel32.dll")
	modAdvapi32     = windows.NewLazySystemDLL("advapi32.dll")

	procCreateNamedPipeW    = modKernel32Pipe.NewProc("CreateNamedPipeW")
	procConnectNamedPipe    = modKernel32Pipe.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe = modKernel32Pipe.NewProc("DisconnectNamedPipe")
	procWaitForSingleObject = modKernel32Pipe.NewProc("WaitForSingleObject")
	procPeekNamedPipe       = modKernel32Pipe.NewProc("PeekNamedPipe")
)

func createPipeName() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf(`\\.\pipe\%s`, hex.EncodeToString(b))
}

func createPipeServer(pipeName string) (windows.Handle, error) {
	namePtr, err := syscall.UTF16PtrFromString(pipeName)
	if err != nil {
		return 0, err
	}

	const (
		PIPE_ACCESS_DUPLEX       = 0x3
		PIPE_TYPE_BYTE           = 0x0
		PIPE_READMODE_BYTE       = 0x0
		PIPE_WAIT                = 0x0
		PIPE_UNLIMITED_INSTANCES = 0xFF
	)

	r, _, err := procCreateNamedPipeW.Call(
		uintptr(unsafe.Pointer(namePtr)),
		PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		65536, // output buffer
		65536, // input buffer
		15000, // timeout ms
		0,
	)
	if r == ^uintptr(0) {
		return 0, fmt.Errorf("CreateNamedPipeW: %w", err)
	}
	return windows.Handle(r), nil
}

func waitPipeConnect(hPipe windows.Handle, timeoutMs uint32) error {
	hEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("CreateEvent: %w", err)
	}
	defer windows.CloseHandle(hEvent)

	ov := windows.Overlapped{HEvent: hEvent}

	r, _, err := procConnectNamedPipe.Call(uintptr(hPipe), uintptr(unsafe.Pointer(&ov)))
	if r != 0 {
		return nil // already connected
	}

	if err == windows.ERROR_PIPE_CONNECTED {
		return nil
	}

	if err != windows.ERROR_IO_PENDING {
		return fmt.Errorf("ConnectNamedPipe: %w", err)
	}

	ret, _, _ := procWaitForSingleObject.Call(uintptr(hEvent), uintptr(timeoutMs))
	if ret != uintptr(windows.WAIT_OBJECT_0) {
		return fmt.Errorf("pipe connect timeout")
	}
	return nil
}

func (s *PipeSession) pipeSend(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("pipe session closed")
	}

	length := uint32(len(data))
	lengthBytes := []byte{
		byte(length),
		byte(length >> 8),
		byte(length >> 16),
		byte(length >> 24),
	}

	var written uint32
	err := windows.WriteFile(s.hPipe, lengthBytes, &written, nil)
	if err != nil || written != 4 {
		return fmt.Errorf("write length: %w", err)
	}

	if length > 0 {
		var totalWritten uint32
		for totalWritten < length {
			var n uint32
			err = windows.WriteFile(s.hPipe, data[totalWritten:], &n, nil)
			if err != nil || n == 0 {
				return fmt.Errorf("write data: %w", err)
			}
			totalWritten += n
		}
	}

	return nil
}

func (s *PipeSession) pipeRecv() (status byte, data []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return 0, nil, fmt.Errorf("pipe session closed")
	}

	var lengthBuf [4]byte
	var totalRead uint32
	deadline := time.Now().Add(10 * time.Second)

	for totalRead < 4 {
		if time.Now().After(deadline) {
			return 0, nil, fmt.Errorf("pipe recv timeout")
		}

		var avail uint32
		r, _, _ := procPeekNamedPipe.Call(uintptr(s.hPipe), 0, 0, 0, uintptr(unsafe.Pointer(&avail)), 0)
		if r == 0 {
			return 0, nil, fmt.Errorf("PeekNamedPipe failed")
		}
		if avail < 4-totalRead {
			time.Sleep(50 * time.Millisecond)
			continue
		}

		var n uint32
		err = windows.ReadFile(s.hPipe, lengthBuf[totalRead:4], &n, nil)
		if err != nil || n == 0 {
			return 0, nil, fmt.Errorf("read length: %w", err)
		}
		totalRead += n
	}

	totalLen := uint32(lengthBuf[0]) | uint32(lengthBuf[1])<<8 | uint32(lengthBuf[2])<<16 | uint32(lengthBuf[3])<<24
	if totalLen < 1 || totalLen > 100*1024*1024 {
		return 0, nil, fmt.Errorf("invalid message length: %d", totalLen)
	}

	buf := make([]byte, totalLen)
	totalRead = 0
	for totalRead < totalLen {
		var n uint32
		err = windows.ReadFile(s.hPipe, buf[totalRead:], &n, nil)
		if err != nil || n == 0 {
			return 0, nil, fmt.Errorf("read data: %w", err)
		}
		totalRead += n
	}

	status = buf[0]
	data = buf[1:]
	return status, data, nil
}

func (s *PipeSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}
	s.closed = true

	s.sendExitLocked()

	time.Sleep(100 * time.Millisecond)

	procDisconnectNamedPipe.Call(uintptr(s.hPipe))
	windows.CloseHandle(s.hPipe)

	if s.ownsProcess && s.hProcess != 0 {
		windows.TerminateProcess(s.hProcess, 0)
		windows.WaitForSingleObject(s.hProcess, 3000)
		windows.CloseHandle(s.hProcess)
	}
}

func (s *PipeSession) sendExitLocked() {
	exitCmd := []byte("EXIT")
	length := uint32(len(exitCmd))
	lengthBytes := []byte{byte(length), byte(length >> 8), byte(length >> 16), byte(length >> 24)}
	windows.WriteFile(s.hPipe, lengthBytes, nil, nil)
	windows.WriteFile(s.hPipe, exitCmd, nil, nil)
}

func (s *PipeSession) GetV20Key(browserName string, encKeyBase64 string) ([]byte, error) {
	cmd := fmt.Sprintf("KEY:%s:%s", browserName, encKeyBase64)
	if err := s.pipeSend([]byte(cmd)); err != nil {
		return nil, fmt.Errorf("send KEY command: %w", err)
	}

	status, data, err := s.pipeRecv()
	if err != nil {
		return nil, fmt.Errorf("recv KEY response: %w", err)
	}

	if status != 0 {
		return nil, fmt.Errorf("decrypt failed: %s", string(data))
	}

	return data, nil
}

func (s *PipeSession) ReadFile(path string) ([]byte, error) {
	cmd := fmt.Sprintf("READ:%s", path)
	if err := s.pipeSend([]byte(cmd)); err != nil {
		return nil, fmt.Errorf("send READ command: %w", err)
	}

	status, data, err := s.pipeRecv()
	if err != nil {
		return nil, fmt.Errorf("recv READ response: %w", err)
	}

	if status != 0 {
		return nil, fmt.Errorf("read failed: %s", string(data))
	}

	return data, nil
}

var ActivePipeSession *PipeSession
