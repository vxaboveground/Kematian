package firefox

import "log"

func logf(format string, args ...interface{}) {
	log.Printf("[firefox] "+format, args...)
}
