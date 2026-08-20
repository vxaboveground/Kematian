package crypto

import "log"

func logf(format string, args ...interface{}) {
	log.Printf("[crypto] "+format, args...)
}
