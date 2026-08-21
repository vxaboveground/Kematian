package fingerprint

import "log"

func logf(format string, args ...interface{}) {
	log.Printf("[fingerprint] "+format, args...)
}
