package health

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

func TestWritePIDFile(t *testing.T) {
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "agent.pid")

	if err := WritePIDFile(pidFile); err != nil {
		t.Fatalf("WritePIDFile failed: %v", err)
	}

	content, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("failed to read PID file: %v", err)
	}

	pid, err := strconv.Atoi(string(content))
	if err != nil {
		t.Fatalf("invalid PID in file: %v", err)
	}

	if pid != os.Getpid() {
		t.Errorf("expected PID %d, got %d", os.Getpid(), pid)
	}
}

// TestCheckHealth_Success runs CheckHealth in a subprocess to test os.Exit(0)
func TestCheckHealth_Success(t *testing.T) {
	if os.Getenv("TEST_CHECK_HEALTH_SUCCESS") == "1" {
		//Create a temporary PID file for this subprocess
		tmpDir := os.TempDir()
		pidFile := filepath.Join(tmpDir, "valid.pid")
		_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600)
		defer os.Remove(pidFile)

		CheckHealth(pidFile)
		return
	}

	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=TestCheckHealth_Success")
	cmd.Env = append(os.Environ(), "TEST_CHECK_HEALTH_SUCCESS=1")
	err := cmd.Run()
	if err != nil {
		t.Fatalf("process ran with err %v, want exit status 0", err)
	}
}

// TestCheckHealth_Failure runs CheckHealth in a subprocess to test os.Exit(1)
func TestCheckHealth_Failure(t *testing.T) {
	if os.Getenv("TEST_CHECK_HEALTH_FAILURE") == "1" {
		CheckHealth("/non/existent/file.pid")
		return
	}

	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=TestCheckHealth_Failure")
	cmd.Env = append(os.Environ(), "TEST_CHECK_HEALTH_FAILURE=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		// Expected exit status 1
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

func TestCheckHealth_InvalidPID(t *testing.T) {
	if os.Getenv("TEST_CHECK_HEALTH_INVALID") == "1" {
		tmpDir := os.TempDir()
		pidFile := filepath.Join(tmpDir, "invalid.pid")
		_ = os.WriteFile(pidFile, []byte("not-a-number"), 0600)
		defer os.Remove(pidFile)

		CheckHealth(pidFile)
		return
	}

	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=TestCheckHealth_InvalidPID")
	cmd.Env = append(os.Environ(), "TEST_CHECK_HEALTH_INVALID=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		// Expected exit status 1
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

func TestCheckHealth_FindProcessError(t *testing.T) {
	if os.Getenv("TEST_CHECK_HEALTH_FINDPROCESS") == "1" {
		// Override findProcess to return error
		findProcess = func(pid int) (*os.Process, error) {
			return nil, fmt.Errorf("mock process lookup error")
		}
		defer func() { findProcess = os.FindProcess }()

		tmpDir := os.TempDir()
		pidFile := filepath.Join(tmpDir, "findprocess.pid")
		_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600)
		defer os.Remove(pidFile)

		CheckHealth(pidFile)
		return
	}

	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=TestCheckHealth_FindProcessError")
	cmd.Env = append(os.Environ(), "TEST_CHECK_HEALTH_FINDPROCESS=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		// Expected exit status 1
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

func TestWritePIDFile_VerifyContent(t *testing.T) {
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "test.pid")

	if err := WritePIDFile(pidFile); err != nil {
		t.Fatalf("WritePIDFile failed: %v", err)
	}

	content, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("failed to read PID file: %v", err)
	}

	pid, err := strconv.Atoi(string(content))
	if err != nil {
		t.Fatalf("PID file content is not a valid integer: %v", err)
	}

	if pid != os.Getpid() {
		t.Errorf("expected PID %d, got %d", os.Getpid(), pid)
	}

	// Verify file permissions are 0600
	info, err := os.Stat(pidFile)
	if err != nil {
		t.Fatalf("failed to stat PID file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected permissions 0600, got %04o", info.Mode().Perm())
	}
}

func TestWritePIDFile_OpenFileExclFails(t *testing.T) {
	// Test the O_EXCL error path: if os.Remove fails to remove an existing file
	// (e.g., it's a directory), then OpenFile with O_EXCL will fail.
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "agent.pid")

	// Create a directory at the pidFile path - os.Remove cannot remove a non-empty dir
	subDir := filepath.Join(pidFile, "subfile")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	err := WritePIDFile(pidFile)
	if err == nil {
		t.Fatal("expected error when path is a non-empty directory, got nil")
	}
}

func TestWritePIDFile_NonExistentDirectory(t *testing.T) {
	pidFile := filepath.Join("/non/existent/directory", "agent.pid")
	err := WritePIDFile(pidFile)
	if err == nil {
		t.Fatal("expected error when writing to non-existent directory, got nil")
	}
}

func TestWritePIDFile_OverwriteExisting(t *testing.T) {
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "agent.pid")

	// Write initial PID file
	if err := os.WriteFile(pidFile, []byte("12345"), 0600); err != nil {
		t.Fatalf("failed to write initial PID file: %v", err)
	}

	// Overwrite with WritePIDFile (it removes existing first)
	if err := WritePIDFile(pidFile); err != nil {
		t.Fatalf("WritePIDFile failed on overwrite: %v", err)
	}

	content, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("failed to read PID file: %v", err)
	}

	pid, err := strconv.Atoi(string(content))
	if err != nil {
		t.Fatalf("PID file content is not a valid integer: %v", err)
	}

	if pid != os.Getpid() {
		t.Errorf("expected current PID %d after overwrite, got %d", os.Getpid(), pid)
	}
}

func TestCheckHealth_StalePID(t *testing.T) {
	if os.Getenv("TEST_CHECK_HEALTH_STALE") == "1" {
		tmpDir := os.TempDir()
		pidFile := filepath.Join(tmpDir, "stale.pid")
		// Use a very large PID that is unlikely to exist
		_ = os.WriteFile(pidFile, []byte("999999"), 0600)
		defer os.Remove(pidFile)

		CheckHealth(pidFile)
		return
	}

	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=TestCheckHealth_StalePID")
	cmd.Env = append(os.Environ(), "TEST_CHECK_HEALTH_STALE=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		// Expected exit status 1 due to stale PID
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}
