//go:build !windows

package platform

import (
	"errors"
)

type PipeSession struct{}

var ActivePipeSession *PipeSession

func (s *PipeSession) Close() {}

func (s *PipeSession) GetV20Key(browserName string, encKeyBase64 string) ([]byte, error) {
	return nil, errors.New("not supported")
}

func (s *PipeSession) ReadFile(path string) ([]byte, error) {
	return nil, errors.New("not supported")
}
