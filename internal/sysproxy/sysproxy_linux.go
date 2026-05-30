//go:build linux

package sysproxy

import (
	"errors"
	"os/exec"
	"strconv"
)

func supported() bool {
	_, err := exec.LookPath("gsettings")
	return err == nil
}

func gset(args ...string) { _ = exec.Command("gsettings", args...).Run() }

func setProxy(mode, host string, port int) error {
	if !supported() {
		return errors.New("gsettings not found — set the system proxy manually (GNOME only is automated)")
	}
	ps := strconv.Itoa(port)
	gset("set", "org.gnome.system.proxy", "mode", "manual")
	if mode == "socks" {
		gset("set", "org.gnome.system.proxy.socks", "host", host)
		gset("set", "org.gnome.system.proxy.socks", "port", ps)
	} else {
		gset("set", "org.gnome.system.proxy.http", "host", host)
		gset("set", "org.gnome.system.proxy.http", "port", ps)
		gset("set", "org.gnome.system.proxy.https", "host", host)
		gset("set", "org.gnome.system.proxy.https", "port", ps)
	}
	return nil
}

func clearProxy() error {
	if !supported() {
		return errors.New("gsettings not found")
	}
	gset("set", "org.gnome.system.proxy", "mode", "none")
	return nil
}
