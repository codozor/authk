//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// detachedProcess is DETACHED_PROCESS: the child has no console.
const detachedProcess = 0x00000008

// setDetachAttrs starts the child without console, in its own process group, so that
// closing the terminal or Ctrl+C in it does not stop the agent.
func setDetachAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess,
	}
}
