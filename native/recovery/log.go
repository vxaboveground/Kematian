package recovery

import (
	"fmt"
	"log"
	"sync"
)

func logf(format string, args ...interface{}) {
	log.Printf("[recovery] "+format, args...)
}

func safeRecover(where string) {
	if r := recover(); r != nil {
		logf("panic recovered in %s: %v", where, r)
	}
}

func recoverErrors(where string, errs *[]string, mu *sync.Mutex) {
	if r := recover(); r != nil {
		logf("panic recovered in %s: %v", where, r)
		mu.Lock()
		*errs = append(*errs, fmt.Sprintf("%s: %v", where, r))
		mu.Unlock()
	}
}
