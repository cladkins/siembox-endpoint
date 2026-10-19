package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
)

// ExtractBinary pulls the agent executable (siembox-agent, or siembox-agent.exe
// for a zip) out of a release archive into dest with mode 0755. At most limit
// bytes are written, which bounds decompression bombs.
func ExtractBinary(archive, dest string, windows bool, limit int64) error {
	if windows {
		return extractZip(archive, dest, "siembox-agent.exe", limit)
	}
	return extractTarGz(archive, dest, "siembox-agent", limit)
}

func extractTarGz(archive, dest, want string, limit int64) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("archive has no %s", want)
		}
		if err != nil {
			return fmt.Errorf("read archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg || path.Base(h.Name) != want {
			continue
		}
		return writeLimited(dest, tr, limit)
	}
}

func extractZip(archive, dest, want string, limit int64) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer zr.Close()
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() || path.Base(zf.Name) != want {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		return writeLimited(dest, rc, limit)
	}
	return fmt.Errorf("archive has no %s", want)
}

func writeLimited(dest string, r io.Reader, limit int64) error {
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(r, limit+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("extracted file exceeds %d bytes", limit)
	}
	if err != nil {
		os.Remove(dest)
		return err
	}
	return os.Chmod(dest, 0o755)
}

// ReplaceExecutable swaps newPath into exe. On unix a rename over the running
// binary is atomic. Windows cannot overwrite a running exe but can rename it, so
// the old file is moved aside to exe+".old" (removed on a later startup) and
// restored if the swap fails.
func ReplaceExecutable(exe, newPath string, windows bool) error {
	if !windows {
		return os.Rename(newPath, exe)
	}
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return fmt.Errorf("move running executable aside: %w", err)
	}
	if err := os.Rename(newPath, exe); err != nil {
		if rerr := os.Rename(old, exe); rerr != nil {
			return fmt.Errorf("place new executable: %v (restoring old failed: %v)", err, rerr)
		}
		return fmt.Errorf("place new executable: %w", err)
	}
	return nil
}
