//go:build windows

package fingerprint

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

// ── Win32 API (raw syscalls) ──────────────────────────────────────

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")

	procGetSystemMetrics         = user32.NewProc("GetSystemMetrics")
	procSystemParametersInfo     = user32.NewProc("SystemParametersInfoW")
	procGetDC                    = user32.NewProc("GetDC")
	procReleaseDC                = user32.NewProc("ReleaseDC")
	procGetDeviceCaps            = gdi32.NewProc("GetDeviceCaps")
	procGetActiveProcessorCount  = kernel32.NewProc("GetActiveProcessorCount")
	procGlobalMemoryStatusEx     = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetUserDefaultLocaleName = kernel32.NewProc("GetUserDefaultLocaleName")
	procGetTimeZoneInformation   = kernel32.NewProc("GetTimeZoneInformation")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type systemTime struct {
	Year         uint16
	Month        uint16
	DayOfWeek    uint16
	Day          uint16
	Hour         uint16
	Minute       uint16
	Second       uint16
	Milliseconds uint16
}

type timeZoneInformation struct {
	Bias         int32
	StandardName [32]uint16
	StandardDate systemTime
	StandardBias int32
	DaylightName [32]uint16
	DaylightDate systemTime
	DaylightBias int32
}

type rect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

// ── Collect ───────────────────────────────────────────────────────

func Collect() *Result {
	r := &Result{
		Platform: "Win32",
		OSArch:   runtime.GOARCH,
	}

	r.OS = osProductName()
	r.HardwareConcurrency = cpuCores()
	r.DeviceMemory = deviceMemoryGB()
	r.MaxTouchPoints = getSystemMetrics(95) // SM_MAXIMUMTOUCHES
	r.ScreenWidth = getSystemMetrics(0)     // SM_CXSCREEN
	r.ScreenHeight = getSystemMetrics(1)    // SM_CYSCREEN

	var work rect
	if systemParametersInfo(0x0030 /*SPI_GETWORKAREA*/, 0, unsafe.Pointer(&work), 0) {
		r.AvailWidth = int(work.Right - work.Left)
		r.AvailHeight = int(work.Bottom - work.Top)
	}

	hdc, _, _ := procGetDC.Call(0)
	if hdc != 0 {
		r.ColorDepth = getDeviceCaps(hdc, 12)       // BITSPIXEL
		if dpi := getDeviceCaps(hdc, 88); dpi > 0 { // LOGPIXELSX
			r.DevicePixelRatio = float64(dpi) / 96.0
		}
		procReleaseDC.Call(0, hdc)
	}

	r.Timezone, r.TimezoneOffset = timezoneInfo()
	r.Languages = languages()
	r.Fonts = fonts()
	r.GPU = gpuName()
	r.Browsers = installedBrowsers()
	r.UserAgent = userAgent(r.Browsers)
	r.LocalIPs = localIPs()

	return r
}

func getSystemMetrics(index int) int {
	v, _, _ := procGetSystemMetrics.Call(uintptr(index))
	return int(v)
}

func systemParametersInfo(uiAction, uiParam uint32, pvParam unsafe.Pointer, fWinIni uint32) bool {
	r, _, _ := procSystemParametersInfo.Call(uintptr(uiAction), uintptr(uiParam), uintptr(pvParam), uintptr(fWinIni))
	return r != 0
}

func getDeviceCaps(hdc uintptr, index int) int {
	v, _, _ := procGetDeviceCaps.Call(hdc, uintptr(index))
	return int(v)
}

func cpuCores() int {
	v, _, _ := procGetActiveProcessorCount.Call(0xffff) // ALL_PROCESSOR_GROUPS
	if v == 0 {
		return runtime.NumCPU()
	}
	return int(v)
}

func deviceMemoryGB() int {
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if r == 0 {
		return 0
	}
	gb := int(ms.TotalPhys / (1 << 30))
	if gb > 8 {
		gb = 8 // navigator.deviceMemory is clamped to 8
	}
	return gb
}

// ── OS ─────────────────────────────────────────────────────────────

func osProductName() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows"
	}
	defer k.Close()

	product, _, _ := k.GetStringValue("ProductName")
	build, _, _ := k.GetStringValue("CurrentBuildNumber")
	display, _, _ := k.GetStringValue("DisplayVersion")
	ubr, _, _ := k.GetStringValue("UBR")

	name := product
	if name == "" {
		name = "Windows"
	}
	ver := display
	if ver == "" && build != "" {
		ver = build
		if ubr != "" {
			ver = build + "." + ubr
		}
	}
	if ver != "" {
		return name + " " + ver
	}
	return name
}

// ── Timezone ──────────────────────────────────────────────────────

// windowsToIANA maps common Windows timezone names to IANA identifiers.
var windowsToIANA = map[string]string{
	"Eastern Standard Time":          "America/New_York",
	"Central Standard Time":          "America/Chicago",
	"Mountain Standard Time":         "America/Denver",
	"Pacific Standard Time":          "America/Los_Angeles",
	"Alaskan Standard Time":          "America/Anchorage",
	"Hawaiian Standard Time":         "Pacific/Honolulu",
	"Atlantic Standard Time":         "America/Halifax",
	"Newfoundland Standard Time":     "America/St_Johns",
	"GMT Standard Time":              "Europe/London",
	"Greenwich Standard Time":        "Atlantic/Reykjavik",
	"W. Europe Standard Time":        "Europe/Berlin",
	"Central Europe Standard Time":   "Europe/Budapest",
	"Romance Standard Time":          "Europe/Paris",
	"Central European Standard Time": "Europe/Warsaw",
	"E. Europe Standard Time":        "Europe/Chisinau",
	"Russian Standard Time":          "Europe/Moscow",
	"Israel Standard Time":           "Asia/Jerusalem",
	"China Standard Time":            "Asia/Shanghai",
	"Tokyo Standard Time":            "Asia/Tokyo",
	"Korea Standard Time":            "Asia/Seoul",
	"Singapore Standard Time":        "Asia/Singapore",
	"India Standard Time":            "Asia/Kolkata",
	"AUS Eastern Standard Time":      "Australia/Sydney",
	"New Zealand Standard Time":      "Pacific/Auckland",
	"SA Pacific Standard Time":       "America/Bogota",
	"Argentina Standard Time":        "America/Argentina/Buenos_Aires",
	"E. South America Standard Time": "America/Sao_Paulo",
}

func timezoneInfo() (string, int) {
	var tzi timeZoneInformation
	r, _, _ := procGetTimeZoneInformation.Call(uintptr(unsafe.Pointer(&tzi)))
	if r == 0xFFFFFFFF {
		return "", 0
	}
	windowsName := syscall.UTF16ToString(tzi.StandardName[:])
	offset := -int(tzi.Bias)

	iana := windowsToIANA[windowsName]
	if iana == "" {
		iana = windowsName
	}
	return iana, offset
}

// ── Languages ─────────────────────────────────────────────────────

func languages() []string {
	var langs []string
	var buf [85]uint16
	r, _, _ := procGetUserDefaultLocaleName.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r > 0 && r <= uintptr(len(buf)) {
		locale := syscall.UTF16ToString(buf[:r])
		if locale != "" {
			langs = append(langs, locale)
		}
	}

	if prefs := chromeAcceptLanguages(); prefs != "" {
		for _, l := range strings.Split(prefs, ",") {
			l = strings.TrimSpace(l)
			if l != "" && !containsStr(langs, l) {
				langs = append(langs, l)
			}
		}
	}
	return langs
}

func chromeAcceptLanguages() string {
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		return ""
	}
	path := filepath.Join(local, `Google\Chrome\User Data\Default\Preferences`)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := string(data)
	idx := strings.Index(s, `"accept_languages"`)
	if idx < 0 {
		return ""
	}
	rest := s[idx:]
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return ""
	}
	rest = rest[colon+1:]
	start := strings.Index(rest, `"`)
	if start < 0 {
		return ""
	}
	rest = rest[start+1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// ── Fonts ─────────────────────────────────────────────────────────

func fonts() []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts`,
		registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()

	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil
	}

	var out []string
	seen := map[string]bool{}
	for _, name := range names {
		f := strings.TrimSpace(name)
		f = strings.TrimSuffix(f, " (TrueType)")
		f = strings.TrimSuffix(f, " (OpenType)")
		f = strings.TrimSuffix(f, " (All res)")
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// ── GPU ───────────────────────────────────────────────────────────

func gpuName() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}`,
		registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()

	subs, _ := k.ReadSubKeyNames(-1)
	for _, sub := range subs {
		if !strings.HasPrefix(sub, "0") {
			continue
		}
		sk, err := registry.OpenKey(k, sub, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		desc, _, _ := sk.GetStringValue("DriverDesc")
		sk.Close()
		desc = strings.TrimSpace(desc)
		if desc == "" || strings.Contains(desc, "Microsoft Basic Display") ||
			strings.Contains(desc, "Microsoft Remote Display") {
			continue
		}
		return desc
	}
	return ""
}

// ── Installed browsers ────────────────────────────────────────────

var browserUpdateGUIDs = []struct {
	name string
	guid string
}{
	{"Chrome", `{8A69D345-D564-463c-AFF1-A69D9E530F96}`},
	{"Edge", `{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}`},
	{"Brave", `{AFE6A462-C574-4B8A-AF43-4CC60DF4563B}`},
}

func installedBrowsers() []Browser {
	var out []Browser
	for _, b := range browserUpdateGUIDs {
		ver := browserVersion(b.guid)
		if ver == "" {
			continue
		}
		out = append(out, Browser{Name: b.name, Version: ver, Path: browserExePath(b.name)})
	}
	return out
}

func browserVersion(guid string) string {
	for _, root := range []string{`SOFTWARE\Google\Update\Clients\`, `SOFTWARE\WOW6432Node\Google\Update\Clients\`} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, root+guid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		pv, _, err := k.GetStringValue("pv")
		k.Close()
		if err == nil && pv != "" {
			return pv
		}
	}
	return ""
}

func browserExePath(name string) string {
	var paths []string
	pf := os.Getenv("ProgramFiles")
	pf86 := os.Getenv("ProgramFiles(x86)")
	switch name {
	case "Chrome":
		paths = []string{
			filepath.Join(pf, `Google\Chrome\Application\chrome.exe`),
			filepath.Join(pf86, `Google\Chrome\Application\chrome.exe`),
		}
	case "Edge":
		paths = []string{
			filepath.Join(pf, `Microsoft\Edge\Application\msedge.exe`),
			filepath.Join(pf86, `Microsoft\Edge\Application\msedge.exe`),
		}
	case "Brave":
		paths = []string{
			filepath.Join(pf, `BraveSoftware\Brave-Browser\Application\brave.exe`),
			filepath.Join(pf86, `BraveSoftware\Brave-Browser\Application\brave.exe`),
		}
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ── User agent ────────────────────────────────────────────────────

func userAgent(browsers []Browser) string {
	order := []string{"Chrome", "Edge", "Brave"}
	version := ""
	for _, want := range order {
		for _, b := range browsers {
			if b.Name == want && b.Version != "" {
				version = b.Version
				break
			}
		}
		if version != "" {
			break
		}
	}
	if version == "" {
		return ""
	}
	return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", version)
}

// ── Local IPs ─────────────────────────────────────────────────────

func localIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ips []string
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil && !v4.IsLoopback() {
				s := v4.String()
				if !containsStr(ips, s) {
					ips = append(ips, s)
				}
			}
		}
	}
	return ips
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
