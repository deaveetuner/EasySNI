//go:build darwin

package sysproxy

import (
	"os/exec"
	"strconv"
	"strings"
)

func supported() bool { return true }

// services lists active network services (Wi-Fi, Ethernet, …).
func services() []string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	var s []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "denotes that") || strings.HasPrefix(line, "*") {
			continue
		}
		s = append(s, line)
	}
	return s
}

func setProxy(mode, host string, port int) error {
	ps := strconv.Itoa(port)
	svcs := services()
	if len(svcs) == 0 {
		return execErr("networksetup", "-listallnetworkservices")
	}
	for _, svc := range svcs {
		if mode == "socks" {
			exec.Command("networksetup", "-setsocksfirewallproxy", svc, host, ps).Run()
			exec.Command("networksetup", "-setsocksfirewallproxystate", svc, "on").Run()
		} else {
			exec.Command("networksetup", "-setwebproxy", svc, host, ps).Run()
			exec.Command("networksetup", "-setsecurewebproxy", svc, host, ps).Run()
			exec.Command("networksetup", "-setwebproxystate", svc, "on").Run()
			exec.Command("networksetup", "-setsecurewebproxystate", svc, "on").Run()
		}
	}
	return nil
}

func clearProxy() error {
	for _, svc := range services() {
		exec.Command("networksetup", "-setsocksfirewallproxystate", svc, "off").Run()
		exec.Command("networksetup", "-setwebproxystate", svc, "off").Run()
		exec.Command("networksetup", "-setsecurewebproxystate", svc, "off").Run()
	}
	return nil
}

func execErr(name string, args ...string) error { return exec.Command(name, args...).Run() }
