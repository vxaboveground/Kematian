package db

import "log"

func logf(format string, args ...interface{}) {
	log.Printf("[db] "+format, args...)
}
