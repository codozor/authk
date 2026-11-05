//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// setDetachAttrs starts the child in a new session: no controlling terminal, so closing
// the terminal (SIGHUP) or Ctrl+C in it does not stop the agent.
func setDetachAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
