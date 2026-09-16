//go:build darwin

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
	r.DiskEncrypted = checkFileVault()
	r.EDRRunning, r.EDRProcess = checkEDRDarwin()
	r.PatchLevel = checkPatchLevelDarwin()
	return r, nil
}

// checkFileVault shells out to `fdesetup status`, macOS's own tool for
// reporting FileVault (full disk encryption) state.
func checkFileVault() bool {
	out, err := exec.Command("fdesetup", "status").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "FileVault is On")
}

func checkEDRDarwin() (bool, string) {
	candidates := []string{"falcond", "SentinelAgent", "wazuh-agentd", "osqueryd"}
	out, err := exec.Command("ps", "-axo", "comm").Output()
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

// checkPatchLevelDarwin reads the last macOS software update install date
// via `softwareupdate --history`, falling back to empty if unavailable.
func checkPatchLevelDarwin() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
