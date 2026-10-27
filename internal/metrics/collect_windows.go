//go:build windows

package metrics

import (
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/cladkins/siembox-endpoint/internal/models"
)

// windowsSource uses kernel32 (system times, memory status, tick count,
// process times and working sets), the volume APIs and iphlpapi interface
// counters, all through golang.org/x/sys without CGO. Windows has no load
// average, so load is not reported.
type windowsSource struct{}

func newSource() (source, error) { return windowsSource{}, nil }

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetTickCount64       = kernel32.NewProc("GetTickCount64")
	procK32GetProcessMemInfo = kernel32.NewProc("K32GetProcessMemoryInfo")
)

func ft(f windows.Filetime) float64 {
	return float64(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) / 1e7 // 100 ns -> s
}

func (windowsSource) cpu() (cpuTimes, int, error) {
	var idle, kernel, user windows.Filetime
	r, _, err := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		return cpuTimes{}, 0, err
	}
	// Kernel time includes idle time.
	total := ft(kernel) + ft(user)
	return cpuTimes{busy: total - ft(idle), total: total}, int(windows.GetActiveProcessorCount(windows.ALL_PROCESSOR_GROUPS)), nil
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func (windowsSource) memory() (memInfo, error) {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if r == 0 {
		return memInfo{}, err
	}
	out := memInfo{total: m.TotalPhys}
	if m.AvailPhys < m.TotalPhys {
		out.used = m.TotalPhys - m.AvailPhys
	}
	// The page file's share of the commit limit stands in for swap.
	if m.TotalPageFile > m.TotalPhys {
		out.swapTotal = m.TotalPageFile - m.TotalPhys
		usedCommit := m.TotalPageFile - m.AvailPageFile
		if usedCommit > out.used {
			out.swapUsed = min(usedCommit-out.used, out.swapTotal)
		}
	}
	return out, nil
}

func (windowsSource) load() (*[3]float64, error) { return nil, nil }

func (windowsSource) uptime() (uint64, error) {
	r, _, _ := procGetTickCount64.Call()
	return uint64(r) / 1000, nil
}

func (windowsSource) disks() ([]models.DiskUsage, error) {
	buf := make([]uint16, 512)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err != nil {
		return nil, err
	}
	var out []models.DiskUsage
	for _, root := range strings.Split(windows.UTF16ToString(buf[:n]), "\x00") {
		if root == "" {
			continue
		}
		p, err := windows.UTF16PtrFromString(root)
		if err != nil || windows.GetDriveType(p) != windows.DRIVE_FIXED {
			continue // removable, network, CD-ROM, RAM disks
		}
		var avail, total, free uint64
		if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil {
			continue
		}
		out = append(out, models.DiskUsage{Mount: strings.TrimSuffix(root, `\`), FSType: "", Total: total, Used: total - free, Free: avail})
	}
	return finishDisks(out, func(models.DiskUsage) string { return "" }), nil
}

func (windowsSource) net() (map[string]netCounter, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := map[string]netCounter{}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		row := windows.MibIfRow2{InterfaceIndex: uint32(ifc.Index)}
		if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row); err != nil {
			continue
		}
		out[ifc.Name] = netCounter{rx: row.InOctets, tx: row.OutOctets}
	}
	return out, nil
}

type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func (windowsSource) processes() ([]rawProc, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []rawProc
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		pid := e.ProcessID
		if pid == 0 {
			continue // System Idle Process
		}
		name := filepath.Base(windows.UTF16ToString(e.ExeFile[:]))
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			continue // protected processes
		}
		var c, x, k, u windows.Filetime
		var rp rawProc
		if windows.GetProcessTimes(h, &c, &x, &k, &u) == nil {
			rp.cpuSec = ft(k) + ft(u)
		}
		var mc processMemoryCounters
		mc.CB = uint32(unsafe.Sizeof(mc))
		if r, _, _ := procK32GetProcessMemInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&mc)), uintptr(mc.CB)); r != 0 {
			rp.rss = uint64(mc.WorkingSetSize)
		}
		windows.CloseHandle(h)
		rp.pid = int(pid)
		rp.name = name
		rp.key = strconv.FormatUint(uint64(pid), 10) + ":" + strconv.FormatUint(uint64(c.HighDateTime)<<32|uint64(c.LowDateTime), 10)
		out = append(out, rp)
	}
	return out, nil
}
