// Package sysproxy sets or clears the operating-system HTTP/SOCKS proxy so the
// whole machine can route through a local proxy (e.g. xray's SOCKS port). Each
// OS is handled with its native tooling (Windows registry, macOS networksetup,
// GNOME gsettings) — no external Go dependencies.
package sysproxy

// SetSOCKS points the OS system proxy at a local SOCKS5 server.
func SetSOCKS(host string, port int) error { return setProxy("socks", host, port) }

// SetHTTP points the OS system proxy at a local HTTP proxy.
func SetHTTP(host string, port int) error { return setProxy("http", host, port) }

// Clear removes the system proxy configuration.
func Clear() error { return clearProxy() }

// Supported reports whether system-proxy control is available on this OS.
func Supported() bool { return supported() }
