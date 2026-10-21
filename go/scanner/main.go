// Linux lab collector. Every scanner runs in its own goroutine and process group.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type scanSpec struct {
	name string
	args []string
}
type scanStatus struct {
	Status   string  `json:"status"`
	Started  float64 `json:"started"`
	Finished float64 `json:"finished"`
	Error    string  `json:"error,omitempty"`
}
type executor func(context.Context, scanSpec, string) error

func execute(ctx context.Context, spec scanSpec, folder string) error {
	log, err := os.Create(filepath.Join(folder, spec.name+".log"))
	if err != nil {
		return err
	}
	defer log.Close()
	cmd := exec.CommandContext(ctx, spec.args[0], spec.args[1:]...)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return nil
}

// The channel is buffered; one failing scanner never prevents collection of others.
func collect(ctx context.Context, specs []scanSpec, folder string, timeout time.Duration, run executor) map[string]scanStatus {
	type result struct {
		name   string
		status scanStatus
	}
	results := make(chan result, len(specs))
	var wg sync.WaitGroup
	for _, s := range specs {
		wg.Add(1)
		go func(spec scanSpec) {
			defer wg.Done()
			start := float64(time.Now().UnixNano()) / 1e9
			child, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			err := run(child, spec, folder)
			status := scanStatus{Status: "completed", Started: start, Finished: float64(time.Now().UnixNano()) / 1e9}
			if err != nil {
				status.Status = "failed"
				status.Error = err.Error()
			}
			results <- result{spec.name, status}
		}(s)
	}
	wg.Wait()
	close(results)
	statuses := make(map[string]scanStatus, len(specs))
	for r := range results {
		statuses[r.name] = r.status
	}
	return statuses
}

func specifications(folder, home, mac string) []scanSpec {
	return []scanSpec{
		{"nmap", []string{"nmap", "-sT", "-sV", "-Pn", "-p8000", "-oX", filepath.Join(folder, "nmap.xml"), "192.0.2.2"}},
		{"masscan", []string{"masscan", "192.0.2.2", "-p8000", "-e", "mc-host", "--router-mac", mac, "--rate", "10", "--wait", "5", "-oJ", filepath.Join(folder, "masscan.json")}},
		{"nikto", []string{"perl", filepath.Join(home, "tools/nikto/program/nikto.pl"), "-h", "http://192.0.2.2:8000", "-Format", "json", "-o", filepath.Join(folder, "nikto.json")}},
	}
}

func run(ctx context.Context, directory string) error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	folder, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	folder, err = filepath.Abs(folder)
	if err != nil {
		return err
	}
	results, err := filepath.EvalSymlinks(filepath.Join(root, "results"))
	if err != nil {
		return err
	}
	if filepath.Dir(folder) != results || !strings.HasPrefix(filepath.Base(folder), "live-") {
		return fmt.Errorf("run directory must be results/live-*")
	}
	if _, err = net.InterfaceByName("mc-host"); err != nil {
		return fmt.Errorf("lab interface missing: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(results, "lab-target-mac.txt"))
	if err != nil {
		return err
	}
	mac := strings.TrimSpace(string(raw))
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return fmt.Errorf("invalid lab MAC")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	statuses := collect(ctx, specifications(folder, home, mac), folder, 6*time.Minute, execute)
	payload, err := json.MarshalIndent(statuses, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(folder, "scanner_status.json.tmp")
	if err = os.WriteFile(tmp, payload, 0600); err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(folder, "scanner_status.json")); err != nil {
		return err
	}
	for _, status := range statuses {
		if status.Status != "completed" {
			return fmt.Errorf("scanner failure: see %s/scanner_status.json", folder)
		}
	}
	return nil
}

func main() {
	directory := flag.String("run-dir", "", "existing results/live-* directory")
	flag.Parse()
	if *directory == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Usage: scan_runner --run-dir results/live-...")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, *directory); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
