package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// authorizeAction triggers Polkit verification using the full <pid>,<start-time>,<uid>
// subject specification to prevent PID-reuse race conditions.
func authorizeAction(actionDesc string) error {
	subject, err := buildPolkitProcessSubject(os.Getpid(), os.Getuid())
	if err != nil {
		return fmt.Errorf("failed to build polkit process subject: %w", err)
	}

	cmd := exec.Command(
		"pkcheck",
		"--action-id", "org.freedesktop.policykit.exec",
		"--process", subject,
		"--allow-user-interaction",
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("polkit authorization denied (%s): %w", actionDesc, err)
	}
	return nil
}

// buildPolkitProcessSubject parses field 22 (starttime) from /proc/<pid>/stat
// and formats "<pid>,<starttime>,<uid>" as required by pkcheck(1).
func buildPolkitProcessSubject(pid, uid int) (string, error) {
	statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	statStr := string(statBytes)

	// Field 2 (comm) is wrapped in parentheses and may contain spaces; find the last ')'
	closeParen := strings.LastIndexByte(statStr, ')')
	if closeParen == -1 || closeParen+2 >= len(statStr) {
		return "", fmt.Errorf("unexpected /proc/%d/stat format", pid)
	}

	// Fields after ')' start at field 3 (state); field 22 (starttime) is index 19 (22 - 3)
	fields := strings.Fields(statStr[closeParen+2:])
	if len(fields) <= 19 {
		return "", fmt.Errorf("insufficient fields in /proc/%d/stat", pid)
	}

	startTime := fields[19]
	return fmt.Sprintf("%d,%s,%d", pid, startTime, uid), nil
}
