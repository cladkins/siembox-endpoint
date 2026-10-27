package metrics

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cladkins/siembox-endpoint/internal/models"
)

func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseProcStat(t *testing.T) {
	ct, n, err := parseProcStat(fixture(t, "proc/stat"))
	if err != nil {
		t.Fatal(err)
	}
	// total = 10000+500+3000+80000+1500+0+200+0; idle = 80000+1500
	if ct.total != 95200 || ct.busy != 13700 || n != 2 {
		t.Fatalf("got %+v cpus=%d", ct, n)
	}
	if _, _, err := parseProcStat([]byte("intr 1 2 3\n")); err == nil {
		t.Fatal("want error without a cpu line")
	}
}

func TestParseMeminfo(t *testing.T) {
	m, err := parseMeminfo(fixture(t, "proc/meminfo"))
	if err != nil {
		t.Fatal(err)
	}
	want := memInfo{
		total:     8048576 * 1024,
		used:      (8048576 - 4024288) * 1024,
		swapTotal: 2097148 * 1024,
		swapUsed:  (2097148 - 1572860) * 1024,
	}
	if m != want {
		t.Fatalf("got %+v want %+v", m, want)
	}
	// Old kernels without MemAvailable: free + buffers + cached + reclaimable.
	old, err := parseMeminfo([]byte("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 200 kB\nSReclaimable: 50 kB\n"))
	if err != nil || old.used != 600*1024 {
		t.Fatalf("fallback: %+v %v", old, err)
	}
	if _, err := parseMeminfo([]byte("garbage")); err == nil {
		t.Fatal("want error without MemTotal")
	}
}

func TestParseLoadUptime(t *testing.T) {
	l, err := parseLoadavg(fixture(t, "proc/loadavg"))
	if err != nil || l != [3]float64{0.52, 0.71, 0.66} {
		t.Fatalf("load %v %v", l, err)
	}
	u, err := parseUptime(fixture(t, "proc/uptime"))
	if err != nil || u != 350735 {
		t.Fatalf("uptime %v %v", u, err)
	}
	if _, err := parseLoadavg([]byte("0.1")); err == nil {
		t.Fatal("want error on short loadavg")
	}
}

func TestParseNetDev(t *testing.T) {
	n, err := parseNetDev(fixture(t, "proc/net/dev"))
	if err != nil {
		t.Fatal(err)
	}
	if n["eth0"] != (netCounter{rx: 1000000000, tx: 200000000}) || len(n) != 4 {
		t.Fatalf("got %+v", n)
	}
}

func TestParseMountsUnescapes(t *testing.T) {
	ms := parseMounts(fixture(t, "proc/self/mounts"))
	var found bool
	for _, m := range ms {
		if m.point == "/mnt/backup disk" && m.fstype == "xfs" {
			found = true
		}
	}
	if !found || len(ms) != 10 {
		t.Fatalf("mounts %+v", ms)
	}
}

func TestParsePidStatOddName(t *testing.T) {
	st, err := parsePidStat(fixture(t, "proc/4242/stat"))
	if err != nil {
		t.Fatal(err)
	}
	if st.name != "my (odd) app" || st.ticks != 40000 || st.startTime != 900000 || st.rssPages != 250000 {
		t.Fatalf("got %+v", st)
	}
	if _, err := parsePidStat([]byte("12 (x) S 1")); err == nil {
		t.Fatal("want error on a short stat")
	}
}

func TestParseVMStat(t *testing.T) {
	total := uint64(16 << 30)
	used, err := parseVMStat(fixture(t, "darwin/vm_stat.txt"), total)
	if err != nil {
		t.Fatal(err)
	}
	if want := total - (20000+280000+10000)*16384; used != want {
		t.Fatalf("used %d want %d", used, want)
	}
}

func TestParseNetstatIB(t *testing.T) {
	n, err := parseNetstatIB(fixture(t, "darwin/netstat-ibn.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if n["en0"] != (netCounter{rx: 6000000000, tx: 700000000}) {
		t.Fatalf("en0 %+v", n["en0"])
	}
	// Link rows without a MAC address (one column fewer) still parse.
	if n["utun3"] != (netCounter{rx: 9000, tx: 12000}) || n["lo0"].rx != 900000000 {
		t.Fatalf("got %+v", n)
	}
	if _, ok := n["gif0"]; !ok {
		t.Fatalf("down interface (gif0*) missing: %+v", n)
	}
}

func TestParsePS(t *testing.T) {
	ps := parsePS(fixture(t, "darwin/ps.txt"))
	if len(ps) != 4 {
		t.Fatalf("got %d", len(ps))
	}
	if ps[1].name != "Google Chrome" || *ps[1].cpuPct != 45.5 || ps[1].rss != 800000*1024 || ps[1].user != "alice" {
		t.Fatalf("chrome %+v", ps[1])
	}
}

// copyTree copies testdata/proc into a temp dir the test may change.
func copyTree(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	src := filepath.Join("testdata", "proc")
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func testProc(root string) *procSource {
	return &procSource{
		root:     root,
		pageSize: 4096,
		statfs: func(p string) (uint64, uint64, uint64, error) {
			switch p {
			case "/":
				return 100 << 30, 60 << 30, 35 << 30, nil
			case "/var/lib/docker/bind": // bind mount of the same device
				return 100 << 30, 60 << 30, 35 << 30, nil
			case "/boot/efi":
				return 512 << 20, 6 << 20, 506 << 20, nil
			case "/mnt/backup disk":
				return 0, 0, 0, errors.New("io error")
			}
			return 0, 0, 0, errors.New("unexpected statfs " + p)
		},
		uidOf: func(dir string) (uint32, bool) { return 0, true },
	}
}

func TestCollectorSampleLinux(t *testing.T) {
	root := copyTree(t)
	clk := &clock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	c := newCollector(testProc(root), clk.now)
	c.Prime(true)

	// One minute later: 600 more jiffies busy of 1200; eth0 received 60 MB.
	clk.t = clk.t.Add(time.Minute)
	write := func(rel, s string) {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("stat", "cpu  10500 500 3100 80600 1500 0 200 0 0 0\ncpu0 1 1 1 1\ncpu1 1 1 1 1\n")
	nd, _ := os.ReadFile(filepath.Join(root, "net/dev"))
	write("net/dev", strings.Replace(string(nd), "eth0: 1000000000", "eth0: 1060000000", 1))

	s, err := c.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if s.CPUPct != 50 || s.CPUCount != 2 {
		t.Fatalf("cpu %v count %d", s.CPUPct, s.CPUCount)
	}
	if s.MemTotal != 8048576*1024 || s.Load1 == nil || *s.Load1 != 0.52 || s.UptimeSec != 350735 {
		t.Fatalf("sample %+v", s)
	}
	// Local filesystems only; the bind mount of / and the failing statfs drop out.
	wantDisks := []models.DiskUsage{
		{Mount: "/", FSType: "ext4", Total: 100 << 30, Used: 60 << 30, Free: 35 << 30},
		{Mount: "/boot/efi", FSType: "vfat", Total: 512 << 20, Used: 6 << 20, Free: 506 << 20},
	}
	if !reflect.DeepEqual(s.Disks, wantDisks) {
		t.Fatalf("disks %+v", s.Disks)
	}
	// lo and veth* are skipped; eth0 1 MB/s in; wlan0 idle.
	wantNet := []models.NetRate{{Iface: "eth0", RxBps: 1000000, TxBps: 0}, {Iface: "wlan0"}}
	if !reflect.DeepEqual(s.Net, wantNet) {
		t.Fatalf("net %+v", s.Net)
	}
}

func TestCollectorFirstSampleWithoutPrime(t *testing.T) {
	c := newCollector(testProc(copyTree(t)), (&clock{t: time.Now()}).now)
	s, err := c.Sample()
	if err != nil {
		t.Fatal(err)
	}
	// No baseline: no CPU rate (not the since-boot average) and no network rates.
	if s.CPUPct != 0 || s.Net != nil {
		t.Fatalf("got %+v", s)
	}
}

func TestCollectorProcesses(t *testing.T) {
	root := copyTree(t)
	clk := &clock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	c := newCollector(testProc(root), clk.now)
	c.Prime(true)
	clk.t = clk.t.Add(5 * time.Minute)
	// pid 4242 used 15000 ticks (150 s) in 300 s: 50% of one CPU; systemd 3 s: 1%.
	b, _ := os.ReadFile(filepath.Join(root, "4242/stat"))
	os.WriteFile(filepath.Join(root, "4242/stat"), []byte(strings.Replace(string(b), " 30000 10000 ", " 40000 15000 ", 1)), 0o644)
	b, _ = os.ReadFile(filepath.Join(root, "1/stat"))
	os.WriteFile(filepath.Join(root, "1/stat"), []byte(strings.Replace(string(b), " 1200 800 ", " 1400 900 ", 1)), 0o644)

	snap, err := c.Processes(10, 8<<30)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.ByCPU) != 2 { // the kernel thread (no RSS) is left out
		t.Fatalf("by cpu %+v", snap.ByCPU)
	}
	app := snap.ByCPU[0]
	if app.PID != 4242 || app.CPUPct != 50 || app.Name != "my (odd) app" || app.User != "root" {
		t.Fatalf("top %+v", app)
	}
	if snap.ByCPU[1].PID != 1 || snap.ByCPU[1].CPUPct != 1 {
		t.Fatalf("second %+v", snap.ByCPU[1])
	}
	if snap.ByMem[0].PID != 4242 || snap.ByMem[0].MemRSS != 250000*4096 || snap.ByMem[0].MemPct != 11.92 {
		t.Fatalf("by mem %+v", snap.ByMem[0])
	}

	// A reused pid (new start time) is not charged the old process's time.
	clk.t = clk.t.Add(5 * time.Minute)
	b, _ = os.ReadFile(filepath.Join(root, "4242/stat"))
	os.WriteFile(filepath.Join(root, "4242/stat"), []byte(strings.Replace(string(b), " 900000 900000000 ", " 999999 900000000 ", 1)), 0o644)
	snap, _ = c.Processes(1, 8<<30)
	if len(snap.ByCPU) != 1 || len(snap.ByMem) != 1 {
		t.Fatalf("top 1: %+v", snap)
	}
	for _, p := range snap.ByCPU {
		if p.PID == 4242 && p.CPUPct != 0 {
			t.Fatalf("reused pid charged: %+v", p)
		}
	}
}

func TestRatesSkipsResetsAndCaps(t *testing.T) {
	prev := map[string]netCounter{"eth0": {rx: 100, tx: 100}, "eth1": {rx: 500, tx: 500}}
	cur := map[string]netCounter{"eth0": {rx: 160, tx: 220}, "eth1": {rx: 10, tx: 10}, "eth2": {rx: 5, tx: 5}}
	got := rates(prev, cur, 60)
	if len(got) != 1 || got[0].Iface != "eth0" || got[0].RxBps != 1 || got[0].TxBps != 2 {
		t.Fatalf("got %+v", got)
	}
	prev, cur = map[string]netCounter{}, map[string]netCounter{}
	for i := 0; i < 40; i++ {
		name := "en" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		prev[name] = netCounter{}
		cur[name] = netCounter{rx: uint64(i)}
	}
	if got := rates(prev, cur, 1); len(got) != MaxInterfaces {
		t.Fatalf("cap: %d", len(got))
	}
}

func TestFinishDisksCap(t *testing.T) {
	var in []models.DiskUsage
	for i := 0; i < 50; i++ {
		in = append(in, models.DiskUsage{Mount: "/data/" + strings.Repeat("x", i+1), Total: 1})
	}
	in = append(in, models.DiskUsage{Mount: "/", Total: 1}, models.DiskUsage{Mount: "/empty", Total: 0})
	out := finishDisks(in, func(models.DiskUsage) string { return "" })
	if len(out) != MaxDisks || out[0].Mount != "/" {
		t.Fatalf("got %d first %q", len(out), out[0].Mount)
	}
}

func TestNewOnThisOS(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Skip(err)
	}
	c.Prime(true)
	s, err := c.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if s.MemTotal == 0 || s.MemUsed == 0 || s.MemUsed > s.MemTotal {
		t.Fatalf("memory %+v", s)
	}
	if _, err := c.Processes(5, s.MemTotal); err != nil {
		t.Fatal(err)
	}
}
