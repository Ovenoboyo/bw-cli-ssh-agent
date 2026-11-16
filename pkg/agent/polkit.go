package agent

import (
	"fmt"
	"os"
	"os/exec"
)

// authorizeSign triggers Polkit verification using the built-in exec action ID.
func authorizeSign(keyName string) error {
	pid := fmt.Sprintf("%d", os.Getpid())
	cmd := exec.Command(
		"pkcheck",
		"--action-id", "org.freedesktop.policykit.exec",
		"--process", pid,
		"--allow-user-interaction",
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("polkit authorization denied for %s: %w", keyName, err)
	}
	return nil
}
