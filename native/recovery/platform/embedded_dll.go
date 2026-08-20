//go:build windows

package platform

import (
	_ "embed"
)

//go:embed recovery-key-extractor.dll
var embeddedDLL []byte

func GetEmbeddedDLL() []byte {
	return embeddedDLL
}
