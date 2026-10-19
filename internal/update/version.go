package update

import (
	"regexp"
	"strconv"
)

var (
	versionRe   = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	requestIDRe = regexp.MustCompile(`^[0-9a-fA-F-]{1,64}$`)
)

// ValidVersion reports whether v is a plain X.Y.Z release version (digits only,
// no leading "v", no prerelease). Only such versions are valid update targets
// and only they may be placed into a download URL.
func ValidVersion(v string) bool {
	_, ok := ParseVersion(v)
	return ok
}

// ValidRequestID reports whether id looks like a UUID-ish token and is safe to
// log, persist and report.
func ValidRequestID(id string) bool { return requestIDRe.MatchString(id) }

// Semver is a numeric X.Y.Z triple.
type Semver [3]int

// ParseVersion parses a strict X.Y.Z string. Each component is limited to nine
// digits so comparison can never overflow.
func ParseVersion(v string) (Semver, bool) {
	var out Semver
	if !versionRe.MatchString(v) {
		return out, false
	}
	part, idx := "", 0
	flush := func() bool {
		if len(part) > 9 {
			return false
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return false
		}
		out[idx] = n
		idx++
		part = ""
		return true
	}
	for _, r := range v {
		if r == '.' {
			if !flush() {
				return out, false
			}
			continue
		}
		part += string(r)
	}
	if !flush() {
		return out, false
	}
	return out, true
}

// Compare returns -1, 0 or 1 as a is lower than, equal to, or higher than b.
func (a Semver) Compare(b Semver) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

// IsDevBuild reports whether current is not a plain X.Y.Z release version
// (for example "dev" or "a8922f4-dirty"). Dev builds may be updated manually.
func IsDevBuild(current string) bool { return !ValidVersion(current) }

// CheckTarget decides whether current may be updated to target. The target must
// be a valid X.Y.Z. A release build must move strictly forward; a dev build has
// no comparable version so any valid target is allowed.
func CheckTarget(current, target string) error {
	t, ok := ParseVersion(target)
	if !ok {
		return errInvalidVersion
	}
	c, ok := ParseVersion(current)
	if !ok {
		return nil // dev build
	}
	if t.Compare(c) <= 0 {
		return &notNewerError{current: current, target: target}
	}
	return nil
}
