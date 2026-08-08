package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"
)

type agentTask struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Args           map[string]string `json:"args"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	IssuedAt       int64             `json:"issued_at"`
	Nonce          string            `json:"nonce"`
	Signature      string            `json:"signature"`
}

type taskValidation struct {
	OK      bool   `json:"ok"`
	Execute bool   `json:"execute"`
	Message string `json:"message"`
}

var (
	taskNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	argKeyRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	argValueRe = regexp.MustCompile(`^[A-Za-z0-9_./:,@ -]{0,256}$`)
)

func registerTaskHandlers(mux *http.ServeMux, cfg agentConfig) {
	mux.HandleFunc("/api/agent/tasks/allowlist", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"tasks": cfg.TaskAllowlist})
	})
	mux.HandleFunc("/api/agent/tasks/validate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var task agentTask
		if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, taskValidation{OK: false, Message: "invalid json"})
			return
		}
		result := validateTask(cfg, task)
		if !result.OK {
			w.WriteHeader(http.StatusBadRequest)
		}
		writeJSON(w, result)
	})
}

func validateTask(cfg agentConfig, task agentTask) taskValidation {
	if !taskNameRe.MatchString(task.Name) {
		return taskValidation{Message: "invalid task name"}
	}
	if !allowedTask(cfg.TaskAllowlist, task.Name) {
		return taskValidation{Message: "task is not allowlisted"}
	}
	if task.Signature == "" {
		return taskValidation{Message: "signature is required"}
	}
	if task.IssuedAt < time.Now().Add(-5*time.Minute).Unix() || task.IssuedAt > time.Now().Add(2*time.Minute).Unix() || !taskNameRe.MatchString(task.Nonce) {
		return taskValidation{Message: "task timestamp or nonce is invalid"}
	}
	if task.TimeoutSeconds < 1 || task.TimeoutSeconds > 300 {
		return taskValidation{Message: "timeout must be between 1 and 300 seconds"}
	}
	for k, v := range task.Args {
		if !argKeyRe.MatchString(k) {
			return taskValidation{Message: "invalid argument key"}
		}
		if !argValueRe.MatchString(v) {
			return taskValidation{Message: "invalid argument value"}
		}
	}
	if err := verifyTaskSignature(cfg.TaskPublicKey, task); err != nil {
		return taskValidation{Message: err.Error()}
	}
	return taskValidation{OK: true, Execute: false, Message: "validated; execution disabled in current build"}
}

func verifyTaskSignature(encodedPublicKey string, task agentTask) error {
	publicKey, err := base64.StdEncoding.DecodeString(encodedPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("task verifier is not configured")
	}
	signature, err := base64.StdEncoding.DecodeString(task.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("task signature is invalid")
	}
	task.Signature = ""
	canonical, err := json.Marshal(task)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), canonical, signature) {
		return errors.New("task signature verification failed")
	}
	return nil
}

func allowedTask(allowlist []string, name string) bool {
	for _, allowed := range allowlist {
		if allowed == name {
			return true
		}
	}
	return false
}
