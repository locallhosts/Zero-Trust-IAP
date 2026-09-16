//go:build windows

package posture

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

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
	r.DiskEncrypted = checkBitLocker()
	r.EDRRunning, r.EDRProcess = checkEDRWindows()
	r.PatchLevel = checkPatchLevelWindows()
	return r, nil
}

// checkBitLocker shells out to manage-bde to check volume encryption
// status for the system drive.
func checkBitLocker() bool {
	out, err := exec.Command("manage-bde", "-status", "C:").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Percentage Encrypted: 100%") ||
		strings.Contains(string(out), "Fully Encrypted")
}

func checkEDRWindows() (bool, string) {
	candidates := []string{"CSFalconService", "SentinelAgent", "MsMpEng", "osqueryd"}
	out, err := exec.Command("tasklist").Output()
	if err != nil {
		return false, ""
	}
	text := string(out)
	for _, c := range candidates {
		if strings.Contains(text, c) {
			return true, c
		}
	}
	return false, ""
}

// checkPatchLevelWindows returns the most recent hotfix install date via
// WMIC, best-effort.
func checkPatchLevelWindows() string {
	out, err := exec.Command("wmic", "qfe", "get", "InstalledOn").Output()
	if err != nil {
		return ""
	}
	lines := strings.Fields(string(out))
	if len(lines) > 1 {
		return lines[len(lines)-1]
	}
	return ""
}
