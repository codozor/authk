//go:build !windows

package main

import "syscall"

// runCommand replaces authk with the command: it only returns on failure.
func runCommand(path string, args, env []string) error {
	return syscall.Exec(path, args, env)
}
