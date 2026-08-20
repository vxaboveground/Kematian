package chromium

import "log"

func logf(format string, args ...interface{}) {
	log.Printf("[chromium] "+format, args...)
}
