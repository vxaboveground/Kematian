package fingerprint

type JSResult struct {
	Canvas          string                 `json:"canvas,omitempty"`
	WebGLRenderer   string                 `json:"webglRenderer,omitempty"`
	WebGLVendor     string                 `json:"webglVendor,omitempty"`
	WebGLVersion    string                 `json:"webglVersion,omitempty"`
	WebGLParams     map[string]interface{} `json:"webglParams,omitempty"`
	WebGLExtensions []string               `json:"webglExtensions,omitempty"`
	Audio           float64                `json:"audio,omitempty"`
}
