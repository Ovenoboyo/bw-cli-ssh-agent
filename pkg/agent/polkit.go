package agent

import (
	"fmt"
	"os"
	"os/exec"
)

// authorizeAction triggers Polkit verification using the built-in exec action ID.
func authorizeAction(actionDesc string) error {
	pid := fmt.Sprintf("%d", os.Getpid())
	cmd := exec.Command(
		"pkcheck",
		"--action-id", "org.freedesktop.policykit.exec",
		"--process", pid,
		"--allow-user-interaction",
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("polkit authorization denied (%s): %w", actionDesc, err)
	}
	return nil
}
