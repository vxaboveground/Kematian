package scanner

import (
	"os"
	"regexp"
	"strings"

	"recovery/recovery/types"
)

// BIP39-valid word counts
var validSeedLengths = map[int]bool{
	12: true, 15: true, 18: true, 21: true, 24: true,
}

const seedScanMaxFileSize = 1 * 1024 * 1024 // 1MB

var seedScanFileExts = map[string]bool{
	".txt": true, ".md": true, ".csv": true, ".tsv": true,
	".log": true, ".rtf": true, ".json": true, ".xml": true,
	".env": true, ".cfg": true, ".conf": true, ".ini": true,
	".bak": true, ".old": true, ".tmp": true, ".note": true,
	".doc": true, ".nfo": true, ".asc": true, ".key": true,
	".pem": true, ".p12": true, ".ppk": true, ".der": true, ".pfx": true,
}

// contentScanExts are the text formats read during the file listing scan to
// look for sensitive plaintext (BIP39 seed phrases, PEM private keys).
var contentScanExts = seedScanFileExts

// privateKeyRe matches PEM private-key header lines. The optional algorithm
// prefix covers RSA/EC/OPENSSH/DSA/ENCRYPTED keys plus the bare PKCS#8 form.
var privateKeyRe = regexp.MustCompile(`(?m)^-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`)

// contentFileTags reads a small text file once and returns the security tags
// that apply to it: "seed" when it contains a BIP39 phrase and "key" when it
// contains a PEM private-key header. Returns nil when the file is not a
// recognized text format or is too large to scan.
func contentFileTags(path, ext string, size int64) []string {
	if !contentScanExts[ext] || size == 0 || size > seedScanMaxFileSize {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var tags []string
	content := strings.ToLower(string(data))
	if looksLikeSeedLine(strings.Fields(content)) {
		tags = append(tags, "seed")
	} else {
		for _, line := range strings.Split(content, "\n") {
			if looksLikeSeedLine(strings.Fields(strings.TrimSpace(line))) {
				tags = append(tags, "seed")
				break
			}
		}
	}
	// PEM headers are case-sensitive, so match against the raw bytes.
	if privateKeyRe.Match(data) {
		tags = append(tags, "key")
	}
	return tags
}

// numberedLineRe strips leading "1." / "1)" / "1:" / "1 -" prefixes from numbered lists
var numberedLineRe = regexp.MustCompile(`^\s*\d{1,2}\s*[.):\-]\s*`)

// ScanSeeds searches collected data for BIP39 seed phrases.
// Checks file contents, password values, and autofill values.
func ScanSeeds(files []types.FileResult, passwords []types.PasswordResult, autofill []types.AutofillResult) []types.SeedResult {
	seen := make(map[string]bool)
	var results []types.SeedResult

	// Scan files
	for _, f := range files {
		if f.Size > seedScanMaxFileSize || f.Size == 0 {
			continue
		}
		if !seedScanFileExts[f.Ext] {
			continue
		}
		data, err := os.ReadFile(f.Path)
		if err != nil {
			continue
		}
		for _, phrase := range extractSeedPhrases(string(data)) {
			if !seen[phrase] {
				seen[phrase] = true
				results = append(results, types.SeedResult{
					Source: "file",
					Path:   f.Path,
					Phrase: phrase,
					Words:  len(strings.Fields(phrase)),
				})
			}
		}
	}

	// Scan passwords
	for _, p := range passwords {
		for _, phrase := range extractSeedPhrases(p.Password) {
			if !seen[phrase] {
				seen[phrase] = true
				results = append(results, types.SeedResult{
					Source: "password",
					Path:   p.URL,
					Phrase: phrase,
					Words:  len(strings.Fields(phrase)),
				})
			}
		}
		for _, phrase := range extractSeedPhrases(p.Username) {
			if !seen[phrase] {
				seen[phrase] = true
				results = append(results, types.SeedResult{
					Source: "password",
					Path:   p.URL,
					Phrase: phrase,
					Words:  len(strings.Fields(phrase)),
				})
			}
		}
	}

	// Scan autofill values
	for _, a := range autofill {
		for _, phrase := range extractSeedPhrases(a.Value) {
			if !seen[phrase] {
				seen[phrase] = true
				results = append(results, types.SeedResult{
					Source: "autofill",
					Path:   a.Name,
					Phrase: phrase,
					Words:  len(strings.Fields(phrase)),
				})
			}
		}
	}

	return results
}

// extractSeedPhrases finds all BIP39-like seed phrases in text content.
// Handles: space-separated, comma-separated, numbered lists, newline-separated.
func extractSeedPhrases(content string) []string {
	if len(content) == 0 {
		return nil
	}

	content = strings.ToLower(content)
	var found []string

	// Strategy 1: full content as one phrase (file contains only the seed)
	if phrase := tryExtractPhrase(content); phrase != "" {
		found = append(found, phrase)
		return found
	}

	// Strategy 2: line-by-line (seed on one line)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if phrase := tryExtractPhrase(line); phrase != "" {
			found = append(found, phrase)
		}
	}

	// Strategy 3: numbered list — collect words from "1. word\n2. word\n..."
	if phrase := tryNumberedList(content); phrase != "" {
		if !containsPhrase(found, phrase) {
			found = append(found, phrase)
		}
	}

	// Strategy 4: comma-separated words
	if strings.Contains(content, ",") {
		normalized := strings.ReplaceAll(content, ",", " ")
		if phrase := tryExtractPhrase(normalized); phrase != "" {
			if !containsPhrase(found, phrase) {
				found = append(found, phrase)
			}
		}
	}

	return found
}

// tryExtractPhrase checks if text contains a valid seed phrase
func tryExtractPhrase(text string) string {
	words := strings.Fields(text)
	if isValidSeedPhrase(words) {
		return strings.Join(words, " ")
	}

	// Try sliding window for phrases embedded in longer text
	for _, count := range []int{24, 21, 18, 15, 12} {
		if len(words) < count {
			continue
		}
		for i := 0; i <= len(words)-count; i++ {
			window := words[i : i+count]
			if isValidSeedPhrase(window) {
				return strings.Join(window, " ")
			}
		}
	}
	return ""
}

// tryNumberedList extracts words from numbered list format:
// "1. abandon\n2. ability\n3. able\n..."
func tryNumberedList(content string) string {
	lines := strings.Split(content, "\n")
	var words []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cleaned := numberedLineRe.ReplaceAllString(line, "")
		cleaned = strings.TrimSpace(cleaned)
		if cleaned == "" {
			continue
		}
		// Each numbered line should have exactly one word
		lineWords := strings.Fields(cleaned)
		if len(lineWords) == 1 && isBIP39Word(lineWords[0]) {
			words = append(words, lineWords[0])
		}
	}
	if isValidSeedPhrase(words) {
		return strings.Join(words, " ")
	}
	return ""
}

func isValidSeedPhrase(words []string) bool {
	if !validSeedLengths[len(words)] {
		return false
	}
	for _, w := range words {
		if !isBIP39Word(w) {
			return false
		}
	}
	return true
}

// isBIP39Word checks if a word matches BIP39 characteristics:
// lowercase a-z only, 3-8 characters.
func isBIP39Word(w string) bool {
	if len(w) < 3 || len(w) > 8 {
		return false
	}
	for _, c := range w {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

func containsPhrase(phrases []string, phrase string) bool {
	for _, p := range phrases {
		if p == phrase {
			return true
		}
	}
	return false
}
