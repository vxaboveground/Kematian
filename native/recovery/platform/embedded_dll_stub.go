//go:build !windows

package platform

func GetEmbeddedDLL() []byte {
	return nil
}
