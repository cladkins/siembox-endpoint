//go:build !linux && !darwin && !windows

package metrics

func newSource() (source, error) { return nil, ErrUnsupported }
