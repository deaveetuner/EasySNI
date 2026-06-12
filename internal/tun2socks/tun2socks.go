// Package tun2socks gives xray a system-wide TUN mode without sing-box. It
// downloads and runs xjasonlyu/tun2socks, which creates a TUN device and
// forwards everything to a local SOCKS5 proxy (xray's SOCKS inbound). The OS
// routing is set best-effort; TUN requires administrator/root.
package tun2socks

import (
	"archive/zip"
	"bytes"
	"errors"
	"ezsni/internal/ghdl"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// LogFunc receives log lines.
type LogFunc func(msg, level string)

func binName() string {
	if runtime.GOOS == "windows" {
		return "tun2socks.exe"
	}
	return "tun2socks"
}

// Find looks for an installed tun2socks binary next to the app or on PATH.
func Find() string {
	var roots []string
	if exe, err := os.Executable(); err == nil {
		roots = append(roots, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		roots = append(roots, wd)
	}
	for _, r := range roots {
		for _, sub := range []string{"", "tun2socks"} {
			dir := filepath.Join(r, sub)
			// exact name first
			p := filepath.Join(dir, binName())
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
			// then any tun2socks* executable (the release binary keeps its
			// full name, e.g. tun2socks-windows-amd64.exe)
			if entries, err := os.ReadDir(dir); err == nil {
				for _, e := range entries {
					n := e.Name()
					if e.IsDir() || !strings.HasPrefix(strings.ToLower(n), "tun2socks") {
						continue
					}
					if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(n), ".exe") {
						continue
					}
					return filepath.Join(dir, n)
				}
			}
		}
	}
	if p, err := exec.LookPath(binName()); err == nil {
		return p
	}
	return ""
}

// ResolveBin returns explicit if set, else the discovered binary.
func ResolveBin(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return Find()
}

// Download fetches the latest xjasonlyu/tun2socks release for this platform.
func Download(destDir string, log LogFunc) (string, error) {
	if log == nil {
		log = func(string, string) {}
	}
	if destDir == "" {
		destDir, _ = os.Getwd()
	}
	osName := runtime.GOOS
	arch := runtime.GOARCH
	want := "tun2socks-" + osName + "-" + arch + ".zip"
	log("Resolving latest tun2socks release…", "ACCENT")
	tag, err := ghdl.LatestTag("xjasonlyu/tun2socks")
	if err != nil {
		return "", err
	}
	url := ghdl.AssetURL("xjasonlyu/tun2socks", tag, want)
	log("Downloading "+want+" ("+tag+")…", "ACCENT")
	data, err := ghdl.Download(url)
	if err != nil {
		return "", err
	}
	paths, err := ghdl.ExtractZip(data, destDir)
	if err != nil {
		return "", err
	}
	bin := ghdl.PickBinary(paths, binName(), "tun2socks")
	if bin == "" {
		return "", errors.New("tun2socks binary not found in archive")
	}
	log("✓ tun2socks extracted to "+destDir, "OK")
	if runtime.GOOS == "windows" {
		if EnsureWintunBeside(filepath.Dir(bin)) != "" {
			log("✓ wintun.dll placed next to tun2socks (from xray-core).", "OK")
		} else {
			log("wintun.dll not found yet — download Xray-core (its zip bundles wintun.dll) and it'll be copied here automatically.", "WARN")
		}
	}
	return bin, nil
}

func extractBinFromZip(data []byte, dest string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	win := runtime.GOOS == "windows"
	var pick *zip.File
	// Prefer a file whose name looks like the tun2socks binary.
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		base := strings.ToLower(filepath.Base(f.Name))
		isExe := !win || strings.HasSuffix(base, ".exe")
		if strings.Contains(base, "tun2socks") && isExe {
			pick = f
			break
		}
	}
	// Fallback: the largest regular file (the binary dwarfs LICENSE/README).
	if pick == nil {
		var maxSize uint64
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			if win && !strings.HasSuffix(strings.ToLower(f.Name), ".exe") {
				continue
			}
			if f.UncompressedSize64 >= maxSize {
				maxSize = f.UncompressedSize64
				pick = f
			}
		}
	}
	if pick == nil {
		return errors.New("tun2socks binary not found in archive")
	}
	rc, err := pick.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, rc)
	return err
}

func device() string {
	switch runtime.GOOS {
	case "windows":
		return "wintun" // requires wintun.dll alongside the binary (as in v2rayN)
	case "darwin":
		return "utun://utun123"
	default:
		return "tun://v2tun0"
	}
}

// wintunDir returns the directory containing wintun.dll (next to the tun2socks
// binary, the app exe, the cwd, or their xray-core/ subfolder), or "".
func wintunDir(bin string) string {
	var dirs []string
	add := func(d string) {
		if d != "" {
			dirs = append(dirs, d, filepath.Join(d, "xray-core"))
		}
	}
	if bin != "" {
		add(filepath.Dir(bin))
	}
	if exe, err := os.Executable(); err == nil {
		add(filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		add(wd)
	}
	for _, d := range dirs {
		if st, err := os.Stat(filepath.Join(d, "wintun.dll")); err == nil && !st.IsDir() {
			return d
		}
	}
	return ""
}

// locateWintunFile returns the path to an existing wintun.dll, searching the
// app/exe/cwd dirs and their xray-core/ subfolders (Xray's archive bundles it),
// or "".
func locateWintunFile() string {
	var dirs []string
	add := func(d string) {
		if d != "" {
			dirs = append(dirs, d, filepath.Join(d, "xray-core"))
		}
	}
	if exe, err := os.Executable(); err == nil {
		add(filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		add(wd)
	}
	for _, d := range dirs {
		p := filepath.Join(d, "wintun.dll")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// EnsureWintunBeside makes sure wintun.dll sits next to the tun2socks binary in
// dir, copying it from wherever it's found (typically the xray-core/ folder, as
// Xray's release zip bundles it). Returns the dll path if present/copied, else
// "". No-op off Windows.
func EnsureWintunBeside(dir string) string {
	if runtime.GOOS != "windows" || dir == "" {
		return ""
	}
	dst := filepath.Join(dir, "wintun.dll")
	if st, err := os.Stat(dst); err == nil && !st.IsDir() {
		return dst
	}
	src := locateWintunFile()
	if src == "" {
		return ""
	}
	if copyFile(src, dst) == nil {
		return dst
	}
	return ""
}

// HasWintun reports whether a wintun.dll is reachable for TUN mode.
func HasWintun() bool { return locateWintunFile() != "" }

// Runner supervises a tun2socks process.
type Runner struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	running bool
	socks   int
	log     LogFunc
}

// NewRunner builds a runner.
func NewRunner(log LogFunc) *Runner {
	if log == nil {
		log = func(string, string) {}
	}
	return &Runner{log: log}
}

// Start launches tun2socks bridging the TUN device to socksHost:socksPort.
// Requires administrator/root. bin may be empty to auto-resolve.
func (r *Runner) Start(bin, socksHost string, socksPort int, excludeIPs []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		r.stopLocked()
	}
	bin = ResolveBin(bin)
	if bin == "" {
		return errors.New("tun2socks binary not found — download it first")
	}
	if socksHost == "" {
		socksHost = "127.0.0.1"
	}
	proxy := "socks5://" + socksHost + ":" + strconv.Itoa(socksPort)
	workDir := ""
	if runtime.GOOS == "windows" {
		EnsureWintunBeside(filepath.Dir(bin)) // copy from xray-core if needed
		if d := wintunDir(bin); d != "" {
			workDir = d // run where wintun.dll lives so Windows can load it
		} else {
			r.log("wintun.dll not found — Windows TUN (wintun) needs it. Download Xray-core (its zip includes wintun.dll) and it'll be used automatically, or get it from https://www.wintun.net.", "WARN")
		}
	}
	args := []string{"-device", device(), "-proxy", proxy, "-loglevel", "warn"}
	cmd := exec.Command(bin, args...)
	if workDir != "" {
		cmd.Dir = workDir
	}
	cmd.Stdout = logWriter{r.log, "INFO"}
	cmd.Stderr = logWriter{r.log, "WARN"}
	if err := cmd.Start(); err != nil {
		return err
	}
	r.cmd = cmd
	r.running = true
	r.socks = socksPort
	r.log("tun2socks started (device "+device()+" → "+proxy+").", "OK")
	// Best-effort: configure the TUN interface IP + system default route so
	// traffic actually flows. Requires admin; failures are logged, not fatal.
	go tunRoutesUp(r.log, excludeIPs)
	go func() {
		_ = cmd.Wait()
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
		tunRoutesDown()
	}()
	return nil
}

func (r *Runner) stopLocked() {
	if r.cmd != nil && r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
	}
	r.cmd = nil
	r.running = false
}

// Stop terminates the tun2socks process.
func (r *Runner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		r.log("tun2socks stopped", "DIM")
	}
	r.stopLocked()
	go tunRoutesDown()
}

// Running reports whether tun2socks is up.
func (r *Runner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

// Status returns a UI snapshot.
func (r *Runner) Status() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]any{"running": r.running, "socks": r.socks, "device": device(), "bin": Find() != ""}
}

type logWriter struct {
	log   LogFunc
	level string
}

func (w logWriter) Write(p []byte) (int, error) {
	msg := string(bytes.TrimSpace(p))
	if msg != "" {
		w.log("[tun2socks] "+msg, w.level)
	}
	return len(p), nil
}
