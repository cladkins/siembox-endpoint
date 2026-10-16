package update

import (
	"errors"
	"fmt"
)

var errInvalidVersion = errors.New("invalid target version (want X.Y.Z)")

type notNewerError struct{ current, target string }

func (e *notNewerError) Error() string {
	return fmt.Sprintf("refusing update: target %s is not newer than current %s", e.target, e.current)
}
