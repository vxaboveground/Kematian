//go:build !windows

package fingerprint

func Collect() *Result {
	return &Result{}
}
