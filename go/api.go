package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

var (
	projectDir string
	mu         sync.Mutex
	reports    = make([]json.RawMessage, 0)
)

func sendJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Use POST", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		var sizeError *http.MaxBytesError
		if errors.As(err, &sizeError) {
			http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "Cannot read request", http.StatusBadRequest)
		}
		return
	}

	if !json.Valid(body) {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	python := filepath.Join(projectDir, ".venv", "bin", "python")
	bridge := filepath.Join(projectDir, "python", "api_bridge.py")

	cmd := exec.CommandContext(ctx, python, bridge)
	cmd.Dir = projectDir
	cmd.Stdin = bytes.NewReader(body)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()

	if err != nil {
		if ctx.Err() != nil {
			http.Error(w, "Analysis timed out or cancelled", http.StatusGatewayTimeout)
			return
		}

		var exitError *exec.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode() == 2 {
			http.Error(w, stderr.String(), http.StatusBadRequest)
			return
		}

		log.Printf("Python error: %v %s", err, stderr.String())
		http.Error(w, "Analysis failed", http.StatusInternalServerError)
		return
	}

	if !json.Valid(output) {
		http.Error(w, "Invalid engine response", http.StatusInternalServerError)
		return
	}

	result := json.RawMessage(output)

	mu.Lock()
	reports = append(reports, result)
	if len(reports) > 100 {
		reports = append([]json.RawMessage(nil), reports[len(reports)-100:]...)
	}
	mu.Unlock()

	sendJSON(w, http.StatusOK, result)
}

func incidentsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Use GET", http.StatusMethodNotAllowed)
		return
	}

	mu.Lock()
	snapshot := make([]json.RawMessage, len(reports))
	copy(snapshot, reports)
	mu.Unlock()

	sendJSON(w, http.StatusOK, snapshot)
}

func main() {
	var err error
	projectDir, err = os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	for _, path := range []string{
		".venv/bin/python",
		"python/api_bridge.py",
		"rules/rules.yaml",
	} {
		_, err = os.Stat(filepath.Join(projectDir, path))
		if err != nil {
			log.Fatalf("Run from the project root missing %s", path)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/analyze", analyzeHandler)
	mux.HandleFunc("/scan", scanHandler)
	mux.HandleFunc("/scan/status", scanStatusHandler)
	mux.HandleFunc("/incidents", incidentsHandler)
	mux.Handle("/", http.FileServer(http.Dir(filepath.Join(projectDir, "web"))))

	server := &http.Server{
		Addr:              "127.0.0.1:8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Println("API listening on http://127.0.0.1:8080")
	log.Fatal(server.ListenAndServe())
}

// A single active lab job prevents overlapping scans and resource exhaustion.
// Only the latest job status is retained; successful reports use the existing history.
type ScanJob struct {
 ID string `json:"id"`
 Status string `json:"status"`
 Target string `json:"target"`
 Error string `json:"error,omitempty"`
 Report json.RawMessage `json:"report,omitempty"`
}
var jobMu sync.Mutex
var latestJob *ScanJob

func scanHandler(w http.ResponseWriter, r *http.Request) {
 if r.Method != http.MethodPost {
  w.Header().Set("Allow", "POST")
  http.Error(w, "Use POST", http.StatusMethodNotAllowed)
  return
 }
 // Require JSON so a cross-origin HTML form cannot start a scan.
 if r.Header.Get("Content-Type") != "application/json" {
  http.Error(w, "Use Content-Type: application/json", http.StatusUnsupportedMediaType)
  return
 }
 r.Body = http.MaxBytesReader(w, r.Body, 1024)
 defer r.Body.Close()
 var request struct { Target string `json:"target"` }
 decoder := json.NewDecoder(r.Body)
 decoder.DisallowUnknownFields()
 if err := decoder.Decode(&request); err != nil {
  http.Error(w, "Invalid scan request", http.StatusBadRequest)
  return
 }
 var extra any
 if err := decoder.Decode(&extra); err != io.EOF {
  http.Error(w, "Expected one JSON object", http.StatusBadRequest)
  return
 }
 if request.Target != "192.0.2.2" {
  http.Error(w, "Only the configured lab target 192.0.2.2 is permitted", http.StatusBadRequest)
  return
 }
 jobMu.Lock()
 if latestJob != nil && latestJob.Status == "running" {
  jobMu.Unlock()
  http.Error(w, "A lab scan is already running", http.StatusConflict)
  return
 }
 job := &ScanJob{ID: time.Now().UTC().Format("20060102T150405.000000000"), Status: "running", Target: request.Target}
 latestJob = job
 snapshot := *job
 jobMu.Unlock()
 go runLabJob(job)
 w.Header().Set("Location", "/scan/status?id="+snapshot.ID)
 sendJSON(w, http.StatusAccepted, snapshot)
}

func runLabJob(job *ScanJob) {
 // The Python runner limits each child process; this deadline is a final guard.
 ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
 defer cancel()
 cmd := exec.CommandContext(ctx, filepath.Join(projectDir, ".venv/bin/python"), filepath.Join(projectDir, "python/live_scan.py"))
 cmd.Dir = projectDir
 var stderr bytes.Buffer
 cmd.Stderr = &stderr
 output, err := cmd.Output()
 jobMu.Lock()
 defer jobMu.Unlock()
 if err != nil || !json.Valid(output) {
  job.Status = "failed"
  job.Error = "Live scan failed: " + stderr.String()
  if ctx.Err() != nil { job.Error = "Scan deadline exceeded" }
  log.Printf("Lab scan failed: %v %s", err, stderr.String())
  return
 }
 result := json.RawMessage(output)
 mu.Lock()
 reports = append(reports, result)
 if len(reports) > 100 { reports = append([]json.RawMessage(nil), reports[len(reports)-100:]...) }
 mu.Unlock()
 job.Report = result
 job.Status = "completed"
}

func scanStatusHandler(w http.ResponseWriter, r *http.Request) {
 if r.Method != http.MethodGet {
  w.Header().Set("Allow", "GET")
  http.Error(w, "Use GET", http.StatusMethodNotAllowed)
  return
 }
 jobMu.Lock()
 defer jobMu.Unlock()
 if latestJob == nil || latestJob.ID != r.URL.Query().Get("id") {
  http.Error(w, "Job not found (only the latest job is retained)", http.StatusNotFound)
  return
 }
 sendJSON(w, http.StatusOK, latestJob)
}
