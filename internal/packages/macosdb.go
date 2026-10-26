package packages

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cladkins/siembox-endpoint/internal/models"
	"github.com/cladkins/siembox-endpoint/internal/util"
)

// The macOS sources: app bundles, Homebrew, installer receipts. The parsing is
// plain Go on directory trees and command output, so it is tested everywhere.

// appDirs are scanned for *.app bundles, and one level below (Utilities, a
// vendor folder). /System/Applications holds Apple's own apps and is left out.
var appDirs = []string{"/Applications"}

// brewPrefixes are Homebrew's install prefixes (Apple silicon, Intel).
var brewPrefixes = []string{"/opt/homebrew", "/usr/local"}

// appBundleSource lists *.app bundles with the version from their Info.plist.
func appBundleSource(dirs []string, readPlist func(path string) (map[string]string, error)) Source {
	return Source{Name: "app", Collect: func(ctx context.Context) ([]models.Package, error) {
		var out []models.Package
		found := false
		for _, dir := range dirs {
			bundles, err := findAppBundles(dir)
			if err != nil {
				continue
			}
			found = true
			for _, b := range bundles {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				info, _ := readPlist(filepath.Join(b, "Contents", "Info.plist"))
				out = append(out, appPackage(b, info))
			}
		}
		if !found {
			return nil, ErrNotPresent
		}
		return out, nil
	}}
}

// findAppBundles returns dir/*.app and dir/*/*.app (not inside a bundle).
func findAppBundles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if strings.HasSuffix(e.Name(), ".app") {
			out = append(out, p)
			continue
		}
		sub, err := os.ReadDir(p)
		if err != nil {
			continue
		}
		for _, s := range sub {
			if s.IsDir() && strings.HasSuffix(s.Name(), ".app") {
				out = append(out, filepath.Join(p, s.Name()))
			}
		}
	}
	return out, nil
}

// appPackage names an app bundle after its folder ("Visual Studio Code.app" →
// "Visual Studio Code"), the name the user sees, with CFBundleShortVersionString
// (else CFBundleVersion) as the version.
func appPackage(bundle string, info map[string]string) models.Package {
	name := strings.TrimSuffix(filepath.Base(bundle), ".app")
	version := info["CFBundleShortVersionString"]
	if version == "" {
		version = info["CFBundleVersion"]
	}
	return models.Package{Name: name, Version: version, Type: "app"}
}

// readInfoPlist reads an Info.plist: XML directly, a binary plist through
// `plutil -convert xml1` (it ships with macOS).
func readInfoPlist(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(raw, []byte("bplist")) {
		bin, ok := util.FindBinary("plutil", []string{"/usr/bin"})
		if !ok {
			return nil, fmt.Errorf("binary plist and no plutil")
		}
		raw, err = runCommand(context.Background(), bin, "-convert", "xml1", "-o", "-", path)
		if err != nil {
			return nil, err
		}
	}
	return ParsePlistStrings(bytes.NewReader(raw))
}

// ParsePlistStrings returns the string values of an XML plist's top-level
// dictionary (nested dictionaries and arrays are skipped).
func ParsePlistStrings(r io.Reader) (map[string]string, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	out := map[string]string{}
	depth := 0 // element depth; the top-level dict's children are at depth 3 (plist > dict > key)
	var key string
	var inKey, inString bool
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 3 {
				text.Reset()
				inKey = t.Name.Local == "key"
				inString = t.Name.Local == "string"
				if !inKey && !inString {
					key = "" // a value of another kind ends the pending key
				}
			}
		case xml.CharData:
			if depth == 3 && (inKey || inString) {
				text.Write(t)
			}
		case xml.EndElement:
			if depth == 3 {
				switch {
				case inKey:
					key = text.String()
				case inString && key != "":
					out[key] = strings.TrimSpace(text.String())
					key = ""
				}
				inKey, inString = false, false
			}
			depth--
		}
	}
}

// brewSource lists Homebrew formulae (Cellar/<name>/<version>) and casks
// (Caskroom/<name>/<version>) under each prefix that has them.
func brewSource(prefixes []string) Source {
	return Source{Name: "brew", Collect: func(context.Context) ([]models.Package, error) {
		var out []models.Package
		found := false
		for _, prefix := range prefixes {
			for _, kind := range []struct{ dir, typ string }{{"Cellar", "brew"}, {"Caskroom", "brew-cask"}} {
				pkgs, err := ListVersionDirs(filepath.Join(prefix, kind.dir), kind.typ)
				if err != nil {
					continue
				}
				found = true
				out = append(out, pkgs...)
			}
		}
		if !found {
			return nil, ErrNotPresent
		}
		return out, nil
	}}
}

// ListVersionDirs reads root/<name>/<version>/ directories (Homebrew's layout).
// Every installed version is listed; hidden entries (.metadata) are skipped.
func ListVersionDirs(root, typ string) ([]models.Package, error) {
	names, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []models.Package
	for _, n := range names {
		if !n.IsDir() || strings.HasPrefix(n.Name(), ".") {
			continue
		}
		versions, err := os.ReadDir(filepath.Join(root, n.Name()))
		if err != nil {
			continue
		}
		for _, v := range versions {
			if v.IsDir() && !strings.HasPrefix(v.Name(), ".") {
				out = append(out, models.Package{Name: n.Name(), Version: v.Name(), Type: typ})
			}
		}
	}
	return out, nil
}

// pkgutilSource lists installer receipts (`pkgutil --pkgs`), skipping Apple's
// own (com.apple.*: OS components), with each one's version from
// `pkgutil --pkg-info`. Receipt ids are reverse-DNS ("org.wireshark.Wireshark").
func pkgutilSource(run func(ctx context.Context, name string, args ...string) ([]byte, error)) Source {
	return Source{Name: "pkgutil", Collect: func(ctx context.Context) ([]models.Package, error) {
		bin, ok := util.FindBinary("pkgutil", []string{"/usr/sbin"})
		if !ok {
			return nil, ErrNotPresent
		}
		raw, err := run(ctx, bin, "--pkgs")
		if err != nil {
			return nil, fmt.Errorf("pkgutil --pkgs: %w", err)
		}
		var out []models.Package
		for _, id := range ParsePkgutilList(raw) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			info, err := run(ctx, bin, "--pkg-info", id)
			version := ""
			if err == nil {
				version = ParsePkgutilInfo(info)
			}
			out = append(out, models.Package{Name: id, Version: version, Type: "pkg"})
		}
		return out, nil
	}}
}

// maxReceipts bounds the per-receipt pkgutil calls.
const maxReceipts = 1000

// ParsePkgutilList returns the non-Apple receipt ids from `pkgutil --pkgs`.
func ParsePkgutilList(raw []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		id := strings.TrimSpace(sc.Text())
		if id == "" || strings.HasPrefix(id, "com.apple.") {
			continue
		}
		out = append(out, id)
		if len(out) == maxReceipts {
			break
		}
	}
	return out
}

// ParsePkgutilInfo returns the "version:" line of `pkgutil --pkg-info <id>`.
func ParsePkgutilInfo(raw []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), ":"); ok && strings.TrimSpace(k) == "version" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
