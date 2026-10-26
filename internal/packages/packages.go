// Package packages lists the software installed on the host — the agent's
// software inventory (SBOM) sent to POST /api/edr/packages. It reads the
// platform's own package databases instead of shelling out to syft/grype:
// grype runs a full filesystem catalog (minutes, high I/O) and its JSON output
// carries only the vulnerable packages, while the package databases are a
// few-millisecond read.
//
//	Linux    dpkg (/var/lib/dpkg/status), apk (/lib/apk/db/installed),
//	         rpm (rpm -qa, when the rpm binary is present)
//	macOS    app bundles (/Applications), Homebrew Cellar/Caskroom,
//	         installer receipts (pkgutil, non-Apple)
//	Windows  the Uninstall registry keys (machine, 32-bit and loaded user hives)
//
// Observe only: everything here reads; nothing changes the host. A source that
// is missing (no rpm, no Homebrew) is skipped; one that fails is logged by the
// caller and the others still count.
package packages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	"github.com/cladkins/siembox-endpoint/internal/models"
)

// Source is one package database on the host.
type Source struct {
	Name string
	// Collect returns the packages it lists. ErrNotPresent means the database
	// is not on this host (not an error worth logging).
	Collect func(ctx context.Context) ([]models.Package, error)
}

// ErrNotPresent reports that a package source does not exist on this host.
var ErrNotPresent = errors.New("package source not present")

// Result is one collection run.
type Result struct {
	Packages []models.Package
	// Sources lists the sources that returned packages, with their counts.
	Sources map[string]int
	// Errors holds the sources that failed (not the ones absent).
	Errors map[string]error
}

// Collect runs every source for this platform and merges their packages,
// de-duplicated and sorted.
func Collect(ctx context.Context) Result {
	return CollectFrom(ctx, platformSources())
}

// CollectFrom runs the given sources (tests pass their own).
func CollectFrom(ctx context.Context, sources []Source) Result {
	res := Result{Sources: map[string]int{}, Errors: map[string]error{}}
	var all []models.Package
	for _, s := range sources {
		if ctx.Err() != nil {
			res.Errors[s.Name] = ctx.Err()
			break
		}
		pkgs, err := s.Collect(ctx)
		if errors.Is(err, ErrNotPresent) {
			continue
		}
		if err != nil {
			res.Errors[s.Name] = err
			continue
		}
		res.Sources[s.Name] = len(pkgs)
		all = append(all, pkgs...)
	}
	res.Packages = Normalize(all)
	return res
}

// Field limits the server applies; longer values are cut here too so the
// agent's hash describes what the server stores.
const (
	maxName    = 256
	maxVersion = 128
)

// Normalize trims and cuts each package, drops nameless ones and duplicates,
// and sorts by type, name, version.
func Normalize(in []models.Package) []models.Package {
	seen := make(map[models.Package]bool, len(in))
	out := make([]models.Package, 0, len(in))
	for _, p := range in {
		p.Name = cut(strings.TrimSpace(p.Name), maxName)
		p.Version = cut(strings.TrimSpace(p.Version), maxVersion)
		p.Type = strings.ToLower(strings.TrimSpace(p.Type))
		if p.Name == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return out
}

// cut shortens s to at most n characters (runes), dropping control characters.
func cut(s string, n int) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if count == n {
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

// Hash identifies a package list independent of order: sha256 over the sorted
// "type\x00name\x00version" lines, as the server computes it.
func Hash(pkgs []models.Package) string {
	lines := make([]string, len(pkgs))
	for i, p := range pkgs {
		lines[i] = p.Type + "\x00" + p.Name + "\x00" + p.Version
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return "sha256:" + hex.EncodeToString(sum[:])
}
