package metrics

import (
	"bufio"
	"bytes"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// The parsers below read the text the collectors get from the OS (/proc on
// Linux, vm_stat / netstat / ps on macOS). They carry no build tags so their
// fixture tests run on every platform.

// parseProcStat reads the aggregate "cpu" line of /proc/stat: busy and total
// jiffies since boot. Idle is idle + iowait; guest time is already counted in
// user/nice, so only the first eight fields are summed.
func parseProcStat(data []byte) (cpuTimes, int, error) {
	var t cpuTimes
	found := false
	count := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		if f[0] != "cpu" {
			count++
			continue
		}
		if len(f) < 5 {
			return t, 0, fmt.Errorf("/proc/stat: short cpu line")
		}
		var vals [8]float64
		for i := 1; i < len(f) && i <= 8; i++ {
			v, err := strconv.ParseFloat(f[i], 64)
			if err != nil {
				return t, 0, fmt.Errorf("/proc/stat: %w", err)
			}
			vals[i-1] = v
		}
		for _, v := range vals {
			t.total += v
		}
		idle := vals[3] + vals[4]
		t.busy = t.total - idle
		found = true
	}
	if !found {
		return t, 0, fmt.Errorf("/proc/stat: no cpu line")
	}
	return t, count, nil
}

// memInfo is what parseMeminfo returns, in bytes.
type memInfo struct {
	total, used, swapTotal, swapUsed uint64
}

// parseMeminfo reads /proc/meminfo. Used is MemTotal - MemAvailable (what
// free(1) calls "used": page cache the kernel can drop is not counted); on
// kernels without MemAvailable (before 3.14) it falls back to
// MemFree + Buffers + Cached + SReclaimable.
func parseMeminfo(data []byte) (memInfo, error) {
	kv := map[string]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		f := strings.Fields(line[i+1:])
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && f[1] == "kB" {
			v *= 1024
		}
		kv[line[:i]] = v
	}
	total, ok := kv["MemTotal"]
	if !ok || total == 0 {
		return memInfo{}, fmt.Errorf("/proc/meminfo: no MemTotal")
	}
	avail, ok := kv["MemAvailable"]
	if !ok {
		avail = kv["MemFree"] + kv["Buffers"] + kv["Cached"] + kv["SReclaimable"]
	}
	m := memInfo{total: total, swapTotal: kv["SwapTotal"]}
	if avail < total {
		m.used = total - avail
	}
	if free := kv["SwapFree"]; free < m.swapTotal {
		m.swapUsed = m.swapTotal - free
	}
	return m, nil
}

// parseLoadavg reads the first three fields of /proc/loadavg.
func parseLoadavg(data []byte) ([3]float64, error) {
	var out [3]float64
	f := strings.Fields(string(data))
	if len(f) < 3 {
		return out, fmt.Errorf("/proc/loadavg: short")
	}
	for i := 0; i < 3; i++ {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			return out, fmt.Errorf("/proc/loadavg: %w", err)
		}
		out[i] = v
	}
	return out, nil
}

// parseUptime reads the first field of /proc/uptime (seconds since boot).
func parseUptime(data []byte) (uint64, error) {
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0, fmt.Errorf("/proc/uptime: empty")
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("/proc/uptime: %q", f[0])
	}
	return uint64(v), nil
}

// parseNetDev reads /proc/net/dev: cumulative received and sent bytes per
// interface.
func parseNetDev(data []byte) (map[string]netCounter, error) {
	out := map[string]netCounter{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue // the two header lines
		}
		name := strings.TrimSpace(line[:i])
		f := strings.Fields(line[i+1:])
		if name == "" || len(f) < 9 {
			continue
		}
		rx, err1 := strconv.ParseUint(f[0], 10, 64)
		tx, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[name] = netCounter{rx: rx, tx: tx}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("/proc/net/dev: no interfaces")
	}
	return out, nil
}

// mount is one line of /proc/self/mounts.
type mount struct {
	device, point, fstype string
}

// parseMounts reads /proc/self/mounts (fstab format; spaces and other
// special characters in paths are octal escapes such as \040).
func parseMounts(data []byte) []mount {
	var out []mount
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 {
			continue
		}
		out = append(out, mount{device: unescapeMount(f[0]), point: unescapeMount(f[1]), fstype: f[2]})
	}
	return out
}

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// pidStat is what parsePidStat reads from /proc/<pid>/stat.
type pidStat struct {
	name      string
	ticks     uint64 // utime + stime, clock ticks
	startTime uint64 // clock ticks after boot (tells a reused pid apart)
	rssPages  uint64
}

// parsePidStat reads /proc/<pid>/stat. The command name is in parentheses
// and may itself contain spaces and parentheses, so fields are counted from
// the LAST ')'.
func parsePidStat(data []byte) (pidStat, error) {
	s := string(data)
	open := strings.IndexByte(s, '(')
	end := strings.LastIndexByte(s, ')')
	if open < 0 || end < open {
		return pidStat{}, fmt.Errorf("stat: no command name")
	}
	f := strings.Fields(s[end+1:])
	// f[0] is field 3 (state); utime 14, stime 15, starttime 22, rss 24.
	if len(f) < 22 {
		return pidStat{}, fmt.Errorf("stat: short")
	}
	num := func(i int) uint64 {
		v, _ := strconv.ParseUint(f[i], 10, 64)
		return v
	}
	rss, _ := strconv.ParseInt(f[21], 10, 64)
	if rss < 0 {
		rss = 0
	}
	return pidStat{
		name:      s[open+1 : end],
		ticks:     num(11) + num(12),
		startTime: num(19),
		rssPages:  uint64(rss),
	}, nil
}

// parseVMStat reads macOS vm_stat output: used memory is total minus free
// and inactive pages (what the OS can hand out without swapping), the
// convention Activity Monitor's "Memory Used" approximates.
func parseVMStat(data []byte, total uint64) (uint64, error) {
	pageSize := uint64(4096)
	pages := map[string]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "page size of") {
			f := strings.Fields(line)
			for i, w := range f {
				if w == "of" && i+1 < len(f) {
					if v, err := strconv.ParseUint(f[i+1], 10, 64); err == nil && v > 0 {
						pageSize = v
					}
				}
			}
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(line[i+1:]), "."), 10, 64)
		if err != nil {
			continue
		}
		pages[strings.TrimSpace(line[:i])] = v
	}
	free, okF := pages["Pages free"]
	inactive, okI := pages["Pages inactive"]
	if !okF || !okI {
		return 0, fmt.Errorf("vm_stat: no free/inactive page counts")
	}
	avail := (free + inactive + pages["Pages speculative"]) * pageSize
	if avail >= total {
		return 0, nil
	}
	return total - avail, nil
}

// parseNetstatIB reads macOS `netstat -ibn`: one <Link#n> row per interface
// carries its cumulative Ibytes and Obytes. Columns are located from the
// header, since the Address column is empty for some interfaces.
func parseNetstatIB(data []byte) (map[string]netCounter, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	var ib, ob, net = -1, -1, -1
	out := map[string]netCounter{}
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if f[0] == "Name" {
			for i, h := range f {
				switch h {
				case "Ibytes":
					ib = i
				case "Obytes":
					ob = i
				case "Network":
					net = i
				}
			}
			continue
		}
		if ib < 0 || ob < 0 || net < 0 || len(f) <= net || !strings.HasPrefix(f[net], "<Link#") {
			continue
		}
		// A link row with no MAC address has one column fewer: count the
		// byte columns from the right (Obytes is second-to-last when Coll
		// follows, as in every macOS release).
		hdrCols := ob + 2 // Obytes then Coll
		shift := hdrCols - len(f)
		ii, oi := ib-shift, ob-shift
		if ii < 0 || oi < 0 || oi >= len(f) {
			continue
		}
		rx, err1 := strconv.ParseUint(f[ii], 10, 64)
		tx, err2 := strconv.ParseUint(f[oi], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		name := strings.TrimSuffix(f[0], "*") // * marks an interface that is down
		if _, seen := out[name]; !seen {
			out[name] = netCounter{rx: rx, tx: tx}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("netstat: no interfaces")
	}
	return out, nil
}

// parsePS reads `ps -A -o pid=,pcpu=,rss=,user=,comm=` (macOS): pid, %CPU of
// one core, resident KiB, user, and the executable (a path; its base name is
// kept). The command is last, so spaces in it are kept.
func parsePS(data []byte) []rawProc {
	var out []rawProc
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		pcpu, err := strconv.ParseFloat(f[1], 64)
		if err != nil {
			continue
		}
		rss, _ := strconv.ParseUint(f[2], 10, 64)
		name := path.Base(strings.Join(f[4:], " "))
		cpu := pcpu
		out = append(out, rawProc{
			key:    strconv.Itoa(pid) + ":" + name,
			pid:    pid,
			name:   name,
			user:   f[3],
			cpuPct: &cpu,
			rss:    rss * 1024,
		})
	}
	return out
}
