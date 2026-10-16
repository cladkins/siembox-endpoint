//go:build !linux && !darwin && !windows

package update

import "errors"

func launchDetached(Command) error {
	return errors.New("self-update is not supported on this platform")
}
