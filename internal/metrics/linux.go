package metrics

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/cladkins/siembox-endpoint/internal/models"
)

// procSource reads a Linux /proc tree. root is "/proc" in production and a
// testdata directory in tests; statfs and uidOf are swapped in tests too.
// It has no build tag (only collect_linux.go wires it in) so its fixture
// tests run everywhere.
type procSource struct {
	root     string
	pageSize uint64
	statfs   func(path string) (total, used, free uint64, err error)
	uidOf    func(path string) (uint32, bool)

	usersMu sync.Mutex
	users   map[uint32]string
}

// clockTicks is USER_HZ, the unit of /proc/<pid>/stat CPU times. It is 100
// on every Linux architecture Go supports (sysconf is not reachable without
// CGO).
const clockTicks = 100

func (p *procSource) read(rel string) ([]byte, error) {
	return os.ReadFile(filepath.Join(p.root, rel))
}

func (p *procSource) cpu() (cpuTimes, int, error) {
	b, err := p.read("stat")
	if err != nil {
		return cpuTimes{}, 0, err
	}
	return parseProcStat(b)
}

func (p *procSource) memory() (memInfo, error) {
	b, err := p.read("meminfo")
	if err != nil {
		return memInfo{}, err
	}
	return parseMeminfo(b)
}

func (p *procSource) load() (*[3]float64, error) {
	b, err := p.read("loadavg")
	if err != nil {
		return nil, err
	}
	l, err := parseLoadavg(b)
	if err != nil {
		return nil, err
	}
	return &l, nil
}

func (p *procSource) uptime() (uint64, error) {
	b, err := p.read("uptime")
	if err != nil {
		return 0, err
	}
	return parseUptime(b)
}

func (p *procSource) net() (map[string]netCounter, error) {
	b, err := p.read("net/dev")
	if err != nil {
		return nil, err
	}
	return parseNetDev(b)
}

// localFS are the filesystem types reported. Everything else is skipped:
// pseudo filesystems (proc, sysfs, cgroup, tmpfs, overlay...), read-only
// images that are always 100% full (squashfs snaps, iso9660), and network
// filesystems, whose statfs can hang for minutes when the server is away.
var localFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
	"f2fs": true, "jfs": true, "reiserfs": true, "vfat": true, "exfat": true, "ntfs": true,
	"ntfs3": true, "fuseblk": true, "bcachefs": true, "hfsplus": true,
}

func (p *procSource) disks() ([]models.DiskUsage, error) {
	b, err := p.read("self/mounts")
	if err != nil {
		return nil, err
	}
	var out []models.DiskUsage
	devices := map[string]string{}
	for _, m := range parseMounts(b) {
		if !localFS[m.fstype] {
			continue
		}
		total, used, free, err := p.statfs(m.point)
		if err != nil {
			continue
		}
		out = append(out, models.DiskUsage{Mount: m.point, FSType: m.fstype, Total: total, Used: used, Free: free})
		devices[m.point] = m.device
	}
	return finishDisks(out, func(d models.DiskUsage) string {
		// btrfs/zfs subvolumes share a device name but not their usage; the
		// same device at the same size and usage is a bind mount.
		return devices[d.Mount] + "|" + strconv.FormatUint(d.Total, 10) + "|" + strconv.FormatUint(d.Used, 10)
	}), nil
}

func (p *procSource) processes() ([]rawProc, error) {
	entries, err := os.ReadDir(p.root)
	if err != nil {
		return nil, err
	}
	out := make([]rawProc, 0, len(entries))
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := filepath.Join(p.root, e.Name())
		b, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			continue // exited meanwhile, or not ours to read
		}
		st, err := parsePidStat(b)
		if err != nil {
			continue
		}
		if st.rssPages == 0 {
			// Kernel threads (kworker, ksoftirqd...): no memory of their own,
			// and nothing an operator reads a top list for.
			continue
		}
		rp := rawProc{
			key:    e.Name() + ":" + strconv.FormatUint(st.startTime, 10),
			pid:    pid,
			name:   st.name,
			cpuSec: float64(st.ticks) / clockTicks,
			rss:    st.rssPages * p.pageSize,
		}
		if uid, ok := p.uidOf(dir); ok {
			rp.user = p.userName(uid)
		}
		out = append(out, rp)
	}
	return out, nil
}

// userName resolves a uid once (os/user reads /etc/passwd without CGO);
// an unknown uid is shown as its number.
func (p *procSource) userName(uid uint32) string {
	p.usersMu.Lock()
	defer p.usersMu.Unlock()
	if p.users == nil {
		p.users = map[uint32]string{}
	}
	if n, ok := p.users[uid]; ok {
		return n
	}
	id := strconv.FormatUint(uint64(uid), 10)
	n := id
	if u, err := user.LookupId(id); err == nil && u.Username != "" {
		n = u.Username
	}
	if len(p.users) < 4096 {
		p.users[uid] = n
	}
	return n
}
