package ziputil

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxZipSize = 50 * 1024 * 1024 // 50 MB

func ZipDirectory(dir string) ([]byte, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("directory not found: %s", dir)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	baseName := filepath.Base(dir)

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		zipEntry := baseName + "/" + filepath.ToSlash(rel)
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		w, err := zw.Create(zipEntry)
		if err != nil {
			return nil
		}
		io.Copy(w, f) //nolint:errcheck
		return nil
	})

	if err := zw.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > maxZipSize {
		return nil, fmt.Errorf("ZIP too large (%d bytes, max %d)", buf.Len(), maxZipSize)
	}
	return buf.Bytes(), nil
}

func ZipFiles(paths []string, baseDir string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for _, p := range paths {
		rel, err := filepath.Rel(baseDir, p)
		if err != nil {
			rel = filepath.Base(p)
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		w, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			f.Close()
			continue
		}
		io.Copy(w, f)
		f.Close()
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > maxZipSize {
		return nil, fmt.Errorf("ZIP too large (%d bytes, max %d)", buf.Len(), maxZipSize)
	}
	return buf.Bytes(), nil
}
