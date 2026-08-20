package crypto

import "strings"

func CleanPassword(data []byte) string {
	s := string(data)
	allPrint := true
	for _, c := range s {
		if c < 32 && c != '\t' && c != '\n' && c != '\r' {
			allPrint = false
			break
		}
	}
	if allPrint {
		return strings.TrimSpace(s)
	}
	if len(data) > 32 {
		s2 := string(data[32:])
		allPrint2 := true
		for _, c := range s2 {
			if c < 32 && c != '\t' && c != '\n' && c != '\r' {
				allPrint2 = false
				break
			}
		}
		if allPrint2 {
			return strings.TrimSpace(s2)
		}
	}
	return ""
}
