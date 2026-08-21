package fingerprint

// Browser is an installed browser and its version.
type Browser struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Path    string `json:"path,omitempty"`
}

// Result is the collected native fingerprint.
type Result struct {
	UserAgent           string    `json:"userAgent"`
	Platform            string    `json:"platform"`
	OS                  string    `json:"os"`
	OSArch              string    `json:"osArch"`
	Languages           []string  `json:"languages"`
	HardwareConcurrency int       `json:"hardwareConcurrency"`
	DeviceMemory        int       `json:"deviceMemory"`
	MaxTouchPoints      int       `json:"maxTouchPoints"`
	ScreenWidth         int       `json:"screenWidth"`
	ScreenHeight        int       `json:"screenHeight"`
	AvailWidth          int       `json:"availWidth"`
	AvailHeight         int       `json:"availHeight"`
	ColorDepth          int       `json:"colorDepth"`
	DevicePixelRatio    float64   `json:"devicePixelRatio"`
	Timezone            string    `json:"timezone"`
	TimezoneOffset      int       `json:"timezoneOffset"`
	Fonts               []string  `json:"fonts"`
	GPU                 string    `json:"gpu"`
	Browsers            []Browser `json:"browsers"`
	LocalIPs            []string  `json:"localIps"`
}
