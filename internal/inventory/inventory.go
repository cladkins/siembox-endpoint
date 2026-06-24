// Package inventory collects host facts about the endpoint. Installed-software
// enumeration is intentionally left to the vuln package's SBOM step (Syft) to
// avoid duplicating package discovery; this package focuses on identity facts.
package inventory

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/cladkins/siembox-edr/internal/models"
	"github.com/cladkins/siembox-edr/internal/version"
)

// Collect gathers host facts into a HostInventory. Software is populated
// elsewhere (vuln SBOM) and left nil here.
func Collect() models.HostInventory {
	host, _ := os.Hostname()
	ip, mac := primaryInterface()
	return models.HostInventory{
		Hostname:     host,
		OS:           runtime.GOOS,
		OSVersion:    osVersion(),
		Arch:         runtime.GOARCH,
		IP:           ip,
		MAC:          mac,
		AgentVersion: version.Version,
		CollectedAt:  time.Now().UTC(),
	}
}

// primaryInterface returns the IPv4 address and MAC of the first non-loopback,
// up interface that has a routable address.
func primaryInterface() (ip, mac string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() {
				continue
			}
			v4 := ipnet.IP.To4()
			if v4 == nil {
				continue // prefer IPv4 for the primary address
			}
			return v4.String(), iface.HardwareAddr.String()
		}
	}
	return "", ""
}

// osVersion returns a best-effort OS version string. Detailed per-OS detection
// (sw_vers on macOS, registry/WMI on Windows) is added with the telemetry
// module; here we read /etc/os-release on Linux and fall back to the GOOS name.
func osVersion() string {
	if runtime.GOOS == "linux" {
		if v := linuxPrettyName(); v != "" {
			return v
		}
	}
	return runtime.GOOS
}

func linuxPrettyName() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return ""
}
