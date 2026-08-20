package scanner

import "log"

func logf(format string, args ...interface{}) {
	log.Printf("[scanner] "+format, args...)
}
