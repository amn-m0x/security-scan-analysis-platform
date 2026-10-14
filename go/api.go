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
	mux.HandleFunc("/incidents", incidentsHandler)

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
