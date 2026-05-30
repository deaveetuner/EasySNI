//go:build !windows && !darwin && !linux

package sysproxy

import "errors"

func supported() bool { return false }

func setProxy(mode, host string, port int) error {
	return errors.New("system proxy control is not supported on this OS")
}

func clearProxy() error {
	return errors.New("system proxy control is not supported on this OS")
}
