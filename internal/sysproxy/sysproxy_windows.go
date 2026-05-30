//go:build windows

package sysproxy

import (
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

const regPath = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func supported() bool { return true }

func reg(args ...string) error {
	cmd := exec.Command("reg", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

func setProxy(mode, host string, port int) error {
	hp := host + ":" + strconv.Itoa(port)
	val := hp
	if mode == "socks" {
		val = "socks=" + hp
	}
	if err := reg("add", regPath, "/v", "ProxyServer", "/t", "REG_SZ", "/d", val, "/f"); err != nil {
		return err
	}
	if err := reg("add", regPath, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", "<local>", "/f"); err != nil {
		return err
	}
	if err := reg("add", regPath, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"); err != nil {
		return err
	}
	refresh()
	return nil
}

func clearProxy() error {
	err := reg("add", regPath, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f")
	refresh()
	return err
}

// refresh notifies WinINET so running apps pick up the change immediately.
func refresh() {
	const (
		settingsChanged = 39 // INTERNET_OPTION_SETTINGS_CHANGED
		refreshOpt      = 37 // INTERNET_OPTION_REFRESH
	)
	dll := syscall.NewLazyDLL("wininet.dll")
	proc := dll.NewProc("InternetSetOptionW")
	proc.Call(0, uintptr(settingsChanged), uintptr(unsafe.Pointer(nil)), 0)
	proc.Call(0, uintptr(refreshOpt), uintptr(unsafe.Pointer(nil)), 0)
}
