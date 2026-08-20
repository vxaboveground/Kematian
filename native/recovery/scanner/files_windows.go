//go:build windows

package scanner

func getScanLocations() []scanLocation {
	return []scanLocation{
		{"Desktop", "Desktop"},
		{"Documents", "Documents"},
		{"Downloads", "Downloads"},
		{`OneDrive\Desktop`, "OneDrive/Desktop"},
		{`OneDrive\Documents`, "OneDrive/Documents"},
		{`OneDrive - Personal\Desktop`, "OneDrive/Desktop"},
		{`OneDrive - Personal\Documents`, "OneDrive/Documents"},
		{`OneDrive - Business\Desktop`, "OneDrive/Desktop"},
		{`OneDrive - Business\Documents`, "OneDrive/Documents"},
	}
}
