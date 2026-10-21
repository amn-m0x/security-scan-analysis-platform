package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConcurrentAndFailure(t *testing.T) {
	started := make(chan string, 3)
	release := make(chan struct{})
	done := make(chan map[string]scanStatus, 1)
	specs := []scanSpec{{name: "nmap"}, {name: "masscan"}, {name: "nikto"}}
	go func() {
		done <- collect(context.Background(), specs, t.TempDir(), time.Second, func(ctx context.Context, s scanSpec, _ string) error {
			started <- s.name
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			if s.name == "masscan" {
				return errors.New("permission denied")
			}
			return nil
		})
	}()
	// A sequential implementation cannot put all three names on the channel.
	for i := 0; i < 3; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("scanners were not concurrent")
		}
	}
	close(release)
	statuses := <-done
	if len(statuses) != 3 || statuses["masscan"].Status != "failed" || statuses["nmap"].Status != "completed" || statuses["nikto"].Status != "completed" {
		t.Fatalf("unexpected statuses: %#v", statuses)
	}
}
func TestExecuteExitAndTimeout(t *testing.T) {
	dir := t.TempDir()
	if err := execute(context.Background(), scanSpec{"bad", []string{"sh", "-c", "echo failed; exit 7"}}, dir); err == nil {
		t.Fatal("nonzero exit ignored")
	}
	data, _ := os.ReadFile(filepath.Join(dir, "bad.log"))
	if !strings.Contains(string(data), "failed") {
		t.Fatal("missing log")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := execute(ctx, scanSpec{"slow", []string{"sh", "-c", "sleep 20 & wait"}}, dir); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("child process group not stopped promptly")
	}
}
func TestFixedTarget(t *testing.T) {
	specs := specifications("/tmp/result", "/tmp/home", "aa:bb:cc:dd:ee:ff")
	for _, s := range specs {
		args := strings.Join(s.args, " ")
		if !strings.Contains(args, "192.0.2.2") || !strings.Contains(args, "8000") {
			t.Fatal(args)
		}
	}
}
