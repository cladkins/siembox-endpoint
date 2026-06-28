package transport

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cladkins/siembox-endpoint/internal/util"
)

// Spool is a simple on-disk FIFO queue of pending payloads. The agent writes a
// payload here whenever a send fails (server unreachable), and a background
// flush replays them in order once connectivity returns. Each payload is a
// single file so partial writes never corrupt the queue.
type Spool struct {
	dir string
	mu  sync.Mutex
}

// NewSpool creates (if needed) and returns a spool rooted at dir.
func NewSpool(dir string) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create spool dir: %w", err)
	}
	return &Spool{dir: dir}, nil
}

// Add enqueues a payload under the given kind ("events" or "vulns"). The
// filename embeds a timestamp so List returns items in roughly chronological
// order. The write is atomic (temp file + rename).
func (s *Spool) Add(kind string, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	name := fmt.Sprintf("%s-%d-%s.json", kind, time.Now().UTC().UnixNano(), util.NewID())
	final := filepath.Join(s.dir, name)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// Entry is a queued payload reference.
type Entry struct {
	Path string
	Kind string
}

// List returns queued entries (excluding in-progress .tmp files) sorted by
// filename, i.e. oldest first.
func (s *Spool) List() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	matches, err := filepath.Glob(filepath.Join(s.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	out := make([]Entry, 0, len(matches))
	for _, m := range matches {
		base := filepath.Base(m)
		kind := base
		if i := strings.IndexByte(base, '-'); i > 0 {
			kind = base[:i]
		}
		out = append(out, Entry{Path: m, Kind: kind})
	}
	return out, nil
}

// Read returns the payload bytes for an entry.
func (s *Spool) Read(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// Remove deletes a successfully replayed entry.
func (s *Spool) Remove(path string) error {
	return os.Remove(path)
}
