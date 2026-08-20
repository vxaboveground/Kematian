package platform

import "log"

func logf(format string, args ...interface{}) {
	log.Printf("[platform] "+format, args...)
}
