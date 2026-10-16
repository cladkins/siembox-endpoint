package update

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var (
	hexSumRe    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	assetNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]*$`)
)

// ParseSHA256SUMS parses sha256sum output ("<64 hex>  <filename>" per line,
// "*" binary marker tolerated) into filename -> lowercase hex digest. It is
// strict: a malformed line, an unsafe filename or conflicting duplicates fail
// the parse, because a checksum file we cannot fully trust must not be used.
func ParseSHA256SUMS(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(line) < 66 || !hexSumRe.MatchString(line[:64]) || (line[64] != ' ') {
			return nil, fmt.Errorf("SHA256SUMS line %d: malformed", n)
		}
		name := strings.TrimPrefix(strings.TrimPrefix(line[65:], " "), "*")
		if !assetNameRe.MatchString(name) {
			return nil, fmt.Errorf("SHA256SUMS line %d: unsafe file name", n)
		}
		sum := strings.ToLower(line[:64])
		if prev, dup := out[name]; dup && prev != sum {
			return nil, fmt.Errorf("SHA256SUMS: conflicting entries for %s", name)
		}
		out[name] = sum
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read SHA256SUMS: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("SHA256SUMS is empty")
	}
	return out, nil
}
