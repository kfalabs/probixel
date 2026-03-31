package health

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

var findProcess = os.FindProcess

// WritePIDFile writes the current process ID to the specified path.
func WritePIDFile(path string) error {
	path = filepath.Clean(path)
	pid := os.Getpid()
	// Remove existing file to prevent symlink attacks
	_ = os.Remove(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%d", pid)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// CheckHealth checks if a process with the PID recorded in pidFile is running.
func CheckHealth(pidFile string) {
	data, err := os.ReadFile(pidFile) //nolint:gosec // G304: Reading internal PID file
	if err != nil {
		fmt.Printf("Health check failed: could not read PID file: %v\n", err)
		os.Exit(1)
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		fmt.Printf("Health check failed: invalid PID in file: %v\n", err)
		os.Exit(1)
	}

	process, err := findProcess(pid)
	if err != nil {
		fmt.Printf("Health check failed: could find process %d: %v\n", pid, err)
		os.Exit(1)
	}

	// On Unix, FindProcess always succeeds. Use signal 0 to check if process exists.
	err = process.Signal(syscall.Signal(0))
	if err != nil {
		fmt.Printf("Health check failed: process %d is not running: %v\n", pid, err)
		os.Exit(1)
	}

	fmt.Printf("Health check passed: process %d is running\n", pid)
	os.Exit(0)
}
