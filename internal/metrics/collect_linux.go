//go:build linux

package metrics

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func newSource() (source, error) {
	return &procSource{
		root:     "/proc",
		pageSize: uint64(os.Getpagesize()),
		statfs:   statfs,
		uidOf:    uidOf,
	}, nil
}

// statfs reports a filesystem as df does: total size, used blocks, and the
// blocks an unprivileged user may still write (root's reserve excluded).
func statfs(path string) (total, used, free uint64, err error) {
	var s unix.Statfs_t
	if err = unix.Statfs(path, &s); err != nil {
		return 0, 0, 0, err
	}
	bs := uint64(s.Bsize)
	total = s.Blocks * bs
	used = (s.Blocks - s.Bfree) * bs
	free = s.Bavail * bs
	return total, used, free, nil
}

func uidOf(dir string) (uint32, bool) {
	fi, err := os.Stat(dir)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
