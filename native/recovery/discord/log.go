package discord

import "log"

func logf(format string, args ...interface{}) {
	log.Printf("[discord] "+format, args...)
}
