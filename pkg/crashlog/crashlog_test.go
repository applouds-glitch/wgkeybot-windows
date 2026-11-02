package crashlog

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Паника Go обязана оказаться в файле вместе со стеком. Паника убивает процесс,
// поэтому она устраивается в дочернем процессе — этом же тест-бинаре.
func TestGoPanicLandsInTheFile(t *testing.T) {
	const marker = "wgk-crash-marker"
	path := filepath.Join(t.TempDir(), "crash.log")
	if err := os.WriteFile(path, []byte("earlier crash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runHelper(t, path, marker, "0")
	if err == nil {
		t.Fatalf("helper exited cleanly:\n%s", out)
	}
	data, _ := os.ReadFile(path)
	got := string(data)
	if !strings.Contains(got, "panic: "+marker) || !strings.Contains(got, "goroutine ") {
		t.Fatalf("panic and its stack are not in the file:\n%s\n--- helper output:\n%s", got, out)
	}
	if !strings.HasPrefix(got, "earlier crash\n") {
		t.Fatalf("the file was not appended to:\n%s", got)
	}
}

// Файл больше предела уезжает в .old до открытия, и паника ложится в новый.
func TestOversizedFileIsSetAsideFirst(t *testing.T) {
	const marker = "wgk-crash-after-rotation"
	path := filepath.Join(t.TempDir(), "crash.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runHelper(t, path, marker, "32"); err == nil {
		t.Fatalf("helper exited cleanly:\n%s", out)
	}
	old, _ := os.ReadFile(path + ".old")
	if string(old) != strings.Repeat("x", 64) {
		t.Fatalf(".old holds %q, want the oversized file", old)
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), "panic: "+marker) {
		t.Fatalf("the new file does not start with the panic:\n%s", data)
	}
}

func runHelper(t *testing.T, path, marker, limit string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPanicHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "WGK_CRASH_FILE="+path, "WGK_CRASH_MARKER="+marker, "WGK_CRASH_LIMIT="+limit)
	return cmd.CombinedOutput()
}

func TestPanicHelper(t *testing.T) {
	path := os.Getenv("WGK_CRASH_FILE")
	if path == "" {
		t.Skip("helper for the panic tests")
	}
	limit := int64(0)
	if os.Getenv("WGK_CRASH_LIMIT") == "32" {
		limit = 32
	}
	if err := Open(path, limit); err != nil {
		t.Fatal(err)
	}
	marker := os.Getenv("WGK_CRASH_MARKER")
	go func() { panic(marker) }()
	time.Sleep(10 * time.Second)
}
