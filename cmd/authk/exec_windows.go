package main

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
)

// runCommand runs the command and returns its exit code as an exitError: Windows
// cannot replace a process.
func runCommand(path string, args, env []string) error {
	cmd := exec.Command(path, args[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Ctrl+C reaches the command too (same console): let it decide when to stop
	signal.Ignore(os.Interrupt)
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return &exitError{code: ee.ExitCode()}
	}
	if err != nil {
		return err
	}
	return nil
}
