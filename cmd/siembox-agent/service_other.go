//go:build !darwin

package main

// controlServiceOS is a no-op on non-macOS platforms: start/stop/restart go
// through the cross-platform kardianos service controller. Returns handled=false
// so the caller uses that path.
func controlServiceOS(cmd string) (handled bool, err error) {
	return false, nil
}
