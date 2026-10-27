//go:build darwin

package metrics

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cladkins/siembox-endpoint/internal/models"
)

// darwinSource: sysctl for memory size, swap, load and boot time;
// getfsstat for disks; and three stock tools without a CGO-free API:
// vm_stat (page counts), netstat -ibn (interface byte counters) and ps
// (per-process %CPU and RSS, whose sum is also the host's CPU use: macOS's
// host_processor_info needs CGO). Each command runs at most once a minute
// with a short timeout.
type darwinSource struct {
	mu     sync.Mutex
	psAt   time.Time
	psList []rawProc
}

func newSource() (source, error) { return &darwinSource{}, nil }

const cmdTimeout = 10 * time.Second

func run(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

// ps runs ps once per 5 s at most (cpu and processes share a reading).
func (d *darwinSource) ps() ([]rawProc, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if time.Since(d.psAt) < 5*time.Second && d.psList != nil {
		return d.psList, nil
	}
	out, err := run("/bin/ps", "-A", "-o", "pid=,pcpu=,rss=,user=,comm=")
	if err != nil {
		return nil, err
	}
	d.psList, d.psAt = parsePS(out), time.Now()
	return d.psList, nil
}

func (d *darwinSource) cpu() (cpuTimes, int, error) {
	procs, err := d.ps()
	if err != nil {
		return cpuTimes{}, 0, err
	}
	n := runtime.NumCPU()
	sum := 0.0
	for _, p := range procs {
		if p.cpuPct != nil {
			sum += *p.cpuPct
		}
	}
	pct := sum / float64(n)
	return cpuTimes{pct: &pct}, n, nil
}

func (d *darwinSource) memory() (memInfo, error) {
	total, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return memInfo{}, err
	}
	m := memInfo{total: total}
	if out, err := run("/usr/bin/vm_stat"); err == nil {
		if used, err := parseVMStat(out, total); err == nil {
			m.used = used
		}
	}
	// struct xsw_usage { u64 total, avail, used; ... }
	if raw, err := unix.SysctlRaw("vm.swapusage"); err == nil && len(raw) >= 24 {
		m.swapTotal = binary.LittleEndian.Uint64(raw[0:8])
		m.swapUsed = binary.LittleEndian.Uint64(raw[16:24])
	}
	return m, nil
}

func (d *darwinSource) load() (*[3]float64, error) {
	// struct loadavg { fixpt_t ldavg[3]; long fscale; } (fscale at offset 16 on 64-bit)
	raw, err := unix.SysctlRaw("vm.loadavg")
	if err != nil {
		return nil, err
	}
	if len(raw) < 24 {
		return nil, errors.New("vm.loadavg: short")
	}
	scale := float64(binary.LittleEndian.Uint64(raw[16:24]))
	if scale == 0 {
		return nil, errors.New("vm.loadavg: zero scale")
	}
	var l [3]float64
	for i := 0; i < 3; i++ {
		l[i] = float64(binary.LittleEndian.Uint32(raw[i*4:i*4+4])) / scale
	}
	return &l, nil
}

func (d *darwinSource) uptime() (uint64, error) {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return 0, err
	}
	boot := time.Unix(tv.Sec, int64(tv.Usec)*1000)
	return uint64(time.Since(boot).Seconds()), nil
}

var darwinFS = map[string]bool{"apfs": true, "hfs": true, "msdos": true, "exfat": true, "ntfs": true}

func (d *darwinSource) disks() ([]models.DiskUsage, error) {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	buf := make([]unix.Statfs_t, n)
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	var out []models.DiskUsage
	devices := map[string]string{}
	for _, s := range buf[:n] {
		fs := unix.ByteSliceToString(s.Fstypename[:])
		mnt := unix.ByteSliceToString(s.Mntonname[:])
		if !darwinFS[fs] || s.Flags&unix.MNT_LOCAL == 0 {
			continue
		}
		// APFS system helper volumes (VM, Preboot, Update...) share the
		// container's space with / and the Data volume; keep only those two.
		if strings.HasPrefix(mnt, "/System/Volumes/") && mnt != "/System/Volumes/Data" {
			continue
		}
		bs := uint64(s.Bsize)
		out = append(out, models.DiskUsage{
			Mount: mnt, FSType: fs,
			Total: s.Blocks * bs, Used: (s.Blocks - s.Bfree) * bs, Free: s.Bavail * bs,
		})
		devices[mnt] = unix.ByteSliceToString(s.Mntfromname[:])
	}
	return finishDisks(out, func(u models.DiskUsage) string { return devices[u.Mount] }), nil
}

func (d *darwinSource) net() (map[string]netCounter, error) {
	out, err := run("/usr/sbin/netstat", "-ibn")
	if err != nil {
		return nil, err
	}
	return parseNetstatIB(bytes.TrimSpace(out))
}

func (d *darwinSource) processes() ([]rawProc, error) { return d.ps() }
