package health

import (
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

	cmd := exec.Command(os.Args[0], "-test.run=TestCheckHealth_Success")
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

	cmd := exec.Command(os.Args[0], "-test.run=TestCheckHealth_Failure")
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

	cmd := exec.Command(os.Args[0], "-test.run=TestCheckHealth_InvalidPID")
	cmd.Env = append(os.Environ(), "TEST_CHECK_HEALTH_INVALID=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		// Expected exit status 1
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
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

	cmd := exec.Command(os.Args[0], "-test.run=TestCheckHealth_StalePID")
	cmd.Env = append(os.Environ(), "TEST_CHECK_HEALTH_STALE=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		// Expected exit status 1 due to stale PID
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}
