// Package metrics samples the host's performance for SIEMBox's Endpoints
// page: CPU, memory, swap, load average, uptime, disk usage per local mount
// and network throughput per interface about once a minute, plus the top
// processes by CPU and by memory every few minutes.
//
// No external dependencies and no CGO: Linux reads /proc, macOS uses sysctl
// plus the stock vm_stat / netstat / ps tools, Windows calls kernel32/iphlpapi
// through golang.org/x/sys. Rates (CPU %, network bytes/s, process CPU %) are
// deltas between two readings, so the Collector keeps the previous one; call
// Prime once at startup so the first Sample covers a real interval.
//
// Cost: one sample reads a handful of small files (or runs two short
// commands on macOS) and statfs's each mount; a process snapshot reads one
// stat file per process. Observe-only: nothing on the host is changed.
package metrics

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cladkins/siembox-endpoint/internal/models"
)

// Bounds on what one sample carries, so a host with hundreds of bind mounts
// or container veth interfaces does not send hundreds of rows a minute.
const (
	MaxDisks      = 32
	MaxInterfaces = 16
	// DefaultTopProcesses is how many processes each top list holds.
	DefaultTopProcesses = 10
	MaxTopProcesses     = 25
)

// ErrUnsupported: this OS has no collector.
var ErrUnsupported = errors.New("performance metrics are not supported on this OS")

// cpuTimes are cumulative busy/total CPU time (any unit). A source that can
// only report an instantaneous percentage sets pct instead.
type cpuTimes struct {
	busy, total float64
	pct         *float64
}

type netCounter struct{ rx, tx uint64 }

// rawProc is one process as a source reads it: cumulative CPU seconds (or a
// ready-made percentage) and resident bytes. key tells a reused pid apart.
type rawProc struct {
	key    string
	pid    int
	name   string
	user   string
	cpuSec float64
	cpuPct *float64
	rss    uint64
}

// source is the per-OS reader (collect_<os>.go).
type source interface {
	cpu() (cpuTimes, int, error)
	memory() (memInfo, error)
	load() (*[3]float64, error) // nil, nil where there is no load average
	uptime() (uint64, error)
	disks() ([]models.DiskUsage, error)
	net() (map[string]netCounter, error)
	processes() ([]rawProc, error)
}

// Collector turns a source's cumulative counters into samples. Safe for one
// goroutine at a time (the agent's metrics loop); the mutex only guards
// against misuse.
type Collector struct {
	mu  sync.Mutex
	src source
	now func() time.Time

	prevCPU   *cpuTimes
	prevNet   map[string]netCounter
	prevNetAt time.Time
	prevProcs map[string]rawProc
	prevPAt   time.Time
}

// New returns the collector for this OS, or ErrUnsupported.
func New() (*Collector, error) {
	src, err := newSource()
	if err != nil {
		return nil, err
	}
	return &Collector{src: src, now: time.Now}, nil
}

func newCollector(src source, now func() time.Time) *Collector {
	return &Collector{src: src, now: now}
}

// Prime takes the baseline readings the first Sample (and, with processes,
// the first Processes) measures from. Errors are ignored: Sample retries.
func (c *Collector) Prime(processes bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if t, _, err := c.src.cpu(); err == nil {
		c.prevCPU = &t
	}
	if n, err := c.src.net(); err == nil {
		c.prevNet, c.prevNetAt = n, now
	}
	if processes {
		if p, err := c.src.processes(); err == nil {
			c.prevProcs, c.prevPAt = index(p), now
		}
	}
}

// Sample reads the host now. A part that fails is left out (zero / empty)
// rather than failing the sample; only a failing memory reading (the one
// field every OS has) is an error.
func (c *Collector) Sample() (models.MetricSample, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	s := models.MetricSample{Timestamp: now.UTC().Truncate(time.Second)}

	mem, err := c.src.memory()
	if err != nil {
		return s, err
	}
	s.MemTotal, s.MemUsed, s.SwapTotal, s.SwapUsed = mem.total, mem.used, mem.swapTotal, mem.swapUsed

	if t, n, err := c.src.cpu(); err == nil {
		s.CPUCount = n
		switch {
		case t.pct != nil:
			s.CPUPct = clampPct(*t.pct)
		case c.prevCPU != nil && t.total > c.prevCPU.total && t.busy >= c.prevCPU.busy:
			s.CPUPct = clampPct((t.busy - c.prevCPU.busy) / (t.total - c.prevCPU.total) * 100)
		}
		c.prevCPU = &t
	}
	if l, err := c.src.load(); err == nil && l != nil {
		a, b, d := round2(l[0]), round2(l[1]), round2(l[2])
		s.Load1, s.Load5, s.Load15 = &a, &b, &d
	}
	if u, err := c.src.uptime(); err == nil {
		s.UptimeSec = u
	}
	if d, err := c.src.disks(); err == nil {
		s.Disks = d
	}
	if n, err := c.src.net(); err == nil {
		if c.prevNet != nil {
			s.Net = rates(c.prevNet, n, now.Sub(c.prevNetAt).Seconds())
		}
		c.prevNet, c.prevNetAt = n, now
	}
	s.CPUPct = round2(s.CPUPct)
	return s, nil
}

// Processes returns the top n processes by CPU (averaged since the previous
// snapshot, or Prime) and by resident memory. memTotal (bytes) scales MemPct.
// Without a baseline it only takes one and returns nil, nil.
func (c *Collector) Processes(n int, memTotal uint64) (*models.ProcessSnapshot, error) {
	if n <= 0 {
		n = DefaultTopProcesses
	}
	if n > MaxTopProcesses {
		n = MaxTopProcesses
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	procs, err := c.src.processes()
	if err != nil {
		return nil, err
	}
	if c.prevProcs == nil && len(procs) > 0 && procs[0].cpuPct == nil {
		// No baseline to measure CPU from (processes were just turned on):
		// this reading becomes it, and the next call reports.
		c.prevProcs, c.prevPAt = index(procs), now
		return nil, nil
	}
	elapsed := now.Sub(c.prevPAt).Seconds()
	list := make([]models.ProcessInfo, 0, len(procs))
	for _, p := range procs {
		info := models.ProcessInfo{PID: p.pid, Name: truncate(p.name, 128), User: truncate(p.user, 64), MemRSS: p.rss}
		switch {
		case p.cpuPct != nil:
			info.CPUPct = *p.cpuPct
		case c.prevProcs != nil && elapsed > 0:
			if prev, ok := c.prevProcs[p.key]; ok && p.cpuSec >= prev.cpuSec {
				info.CPUPct = (p.cpuSec - prev.cpuSec) / elapsed * 100
			}
		}
		info.CPUPct = round2(info.CPUPct)
		if memTotal > 0 {
			info.MemPct = round2(float64(p.rss) / float64(memTotal) * 100)
		}
		list = append(list, info)
	}
	c.prevProcs, c.prevPAt = index(procs), now
	return &models.ProcessSnapshot{
		Timestamp: now.UTC().Truncate(time.Second),
		ByCPU:     top(list, n, func(a, b models.ProcessInfo) bool { return a.CPUPct > b.CPUPct }),
		ByMem:     top(list, n, func(a, b models.ProcessInfo) bool { return a.MemRSS > b.MemRSS }),
	}, nil
}

func index(procs []rawProc) map[string]rawProc {
	m := make(map[string]rawProc, len(procs))
	for _, p := range procs {
		m[p.key] = p
	}
	return m
}

func top(list []models.ProcessInfo, n int, less func(a, b models.ProcessInfo) bool) []models.ProcessInfo {
	cp := append([]models.ProcessInfo(nil), list...)
	sort.SliceStable(cp, func(i, j int) bool {
		if less(cp[i], cp[j]) {
			return true
		}
		if less(cp[j], cp[i]) {
			return false
		}
		return cp[i].PID < cp[j].PID
	})
	if len(cp) > n {
		cp = cp[:n]
	}
	return cp
}

// rates turns two counter readings into bytes/s per interface, skipping
// loopback and container veth pairs, interfaces that appeared or whose
// counters went backwards (a reset), and keeping the busiest MaxInterfaces.
func rates(prev, cur map[string]netCounter, seconds float64) []models.NetRate {
	if seconds <= 0 {
		return nil
	}
	var out []models.NetRate
	for name, c := range cur {
		if skipInterface(name) {
			continue
		}
		p, ok := prev[name]
		if !ok || c.rx < p.rx || c.tx < p.tx {
			continue
		}
		out = append(out, models.NetRate{
			Iface: name,
			RxBps: round2(float64(c.rx-p.rx) / seconds),
			TxBps: round2(float64(c.tx-p.tx) / seconds),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		ti, tj := out[i].RxBps+out[i].TxBps, out[j].RxBps+out[j].TxBps
		if ti != tj {
			return ti > tj
		}
		return out[i].Iface < out[j].Iface
	})
	if len(out) > MaxInterfaces {
		out = out[:MaxInterfaces]
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Iface < out[j].Iface })
	return out
}

func skipInterface(name string) bool {
	if name == "lo" || strings.HasPrefix(name, "lo0") || name == "Loopback Pseudo-Interface 1" {
		return true
	}
	for _, p := range []string{"veth", "cali", "docker_gwbridge", "gif", "stf", "anpi", "ap1", "awdl", "llw", "utun", "bridge0"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// finishDisks drops empty filesystems and duplicates (the same device
// mounted twice), sorts by mount point and caps the list at MaxDisks
// (shortest paths first, so / and /home win over deep bind mounts).
func finishDisks(in []models.DiskUsage, device func(models.DiskUsage) string) []models.DiskUsage {
	seen := map[string]bool{}
	sort.SliceStable(in, func(i, j int) bool {
		if len(in[i].Mount) != len(in[j].Mount) {
			return len(in[i].Mount) < len(in[j].Mount)
		}
		return in[i].Mount < in[j].Mount
	})
	var out []models.DiskUsage
	for _, d := range in {
		if d.Total == 0 {
			continue
		}
		if key := device(d); key != "" {
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		d.Mount = truncate(d.Mount, 256)
		out = append(out, d)
		if len(out) == MaxDisks {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mount < out[j].Mount })
	return out
}

func clampPct(v float64) float64 {
	if v < 0 || v != v {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func round2(v float64) float64 {
	if v != v {
		return 0
	}
	return float64(int64(v*100+0.5)) / 100
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
