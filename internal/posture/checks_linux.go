//go:build linux

package posture

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// LocalChecker inspects the machine it runs on. Every check here is
// best-effort and defaults to the "less trusted" answer on any error —
// posture checks should fail closed.
type LocalChecker struct {
	DeviceID string
}

func NewLocalChecker(deviceID string) *LocalChecker {
	return &LocalChecker{DeviceID: deviceID}
}

func (l *LocalChecker) Check(ctx context.Context) (Report, error) {
	r := Report{
		DeviceID:  l.DeviceID,
		OS:        runtime.GOOS,
		CheckedAt: time.Now(),
	}
	r.DiskEncrypted = checkDiskEncryptionLinux()
	r.EDRRunning, r.EDRProcess = checkEDRLinux()
	r.PatchLevel = checkPatchLevelLinux()
	return r, nil
}

// checkDiskEncryptionLinux looks for an active LUKS mapping under
// /dev/mapper, which is how most full-disk-encryption setups on Linux
// (dm-crypt/LUKS) show up. This is a heuristic, not a guarantee — a real
// fleet posture tool would also check the actual root/home mount's
// underlying device.
func checkDiskEncryptionLinux() bool {
	out, err := exec.Command("lsblk", "-o", "TYPE").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "crypt")
}

// checkEDRLinux scans the process list for common EDR/AV agent process
// names. Extend this list to match whatever your org actually deploys
// (CrowdStrike falcon-sensor, SentinelOne, osquery, wazuh-agent, etc).
func checkEDRLinux() (bool, string) {
	candidates := []string{"falcon-sensor", "sentinelone", "wazuh-agent", "osqueryd", "crowdstrike"}
	procDirs, err := os.ReadDir("/proc")
	if err != nil {
		return false, ""
	}
	for _, d := range procDirs {
		if !d.IsDir() {
			continue
		}
		commPath := "/proc/" + d.Name() + "/comm"
		f, err := os.Open(commPath)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		if scanner.Scan() {
			name := strings.TrimSpace(scanner.Text())
			for _, c := range candidates {
				if strings.Contains(name, c) {
					f.Close()
					return true, name
				}
			}
		}
		f.Close()
	}
	return false, ""
}

// checkPatchLevelLinux returns the modification date of the apt/dpkg or
// rpm package database as a rough proxy for "last patched" — good enough
// for a portfolio demo; a real implementation would query the package
// manager for pending security updates.
func checkPatchLevelLinux() string {
	candidates := []string{"/var/lib/dpkg/status", "/var/lib/rpm/Packages"}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil {
			return fi.ModTime().Format("2006-01-02")
		}
	}
	return ""
}
