//go:build !windows

package scanner

func getScanLocations() []scanLocation {
	return []scanLocation{
		{"Desktop", "Desktop"},
		{"Documents", "Documents"},
		{"Downloads", "Downloads"},
		{".local/share", ".local/share"},
		{"Dropbox", "Dropbox"},
		{"snap", "Snap"},
	}
}
