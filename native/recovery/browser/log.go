package browser

import "log"

func logf(format string, args ...interface{}) {
	log.Printf("[browser] "+format, args...)
}
