//go:build !linux && !darwin && !windows

package packages

func platformSources() []Source { return nil }
