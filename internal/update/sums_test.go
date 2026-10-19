package update

import (
	"strings"
	"testing"
)

const h1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const h2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

func TestParseSHA256SUMS(t *testing.T) {
	good, err := ParseSHA256SUMS(strings.NewReader(h1 + "  a.deb\n" + h2 + " *b.pkg\r\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if good["a.deb"] != h1 || good["b.pkg"] != strings.ToLower(h2) || len(good) != 2 {
		t.Fatalf("got %v", good)
	}
	for name, in := range map[string]string{
		"empty":        "",
		"short hash":   "abc  a.deb\n",
		"no filename":  h1 + "  \n",
		"path":         h1 + "  ../etc/passwd\n",
		"subdir":       h1 + "  dir/a.deb\n",
		"bad hex":      strings.Repeat("z", 64) + "  a\n",
		"conflict":     h1 + "  a\n" + strings.ToLower(h2) + "  a\n",
		"leading dot":  h1 + "  .hidden\n",
		"no separator": h1 + "a.deb\n",
	} {
		if _, err := ParseSHA256SUMS(strings.NewReader(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
