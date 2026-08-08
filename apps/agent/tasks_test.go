package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestValidateTaskAcceptsAllowlistedSignedTask(t *testing.T) {
	cfg, task := signedTask(t)
	result := validateTask(cfg, task)
	if !result.OK || result.Execute {
		t.Fatalf("unexpected validation result: %+v", result)
	}
}

func TestValidateTaskRejectsUnknownTask(t *testing.T) {
	cfg, task := signedTask(t)
	task.Name = "shell"
	result := validateTask(cfg, task)
	if result.OK {
		t.Fatalf("unknown task was accepted: %+v", result)
	}
}

func TestValidateTaskRejectsShellCharacters(t *testing.T) {
	cfg, task := signedTask(t)
	task.Args["host"] = "127.0.0.1; rm -rf /"
	result := validateTask(cfg, task)
	if result.OK {
		t.Fatalf("shell metacharacters were accepted: %+v", result)
	}
}

func TestValidateTaskRejectsTamperedSignature(t *testing.T) {
	cfg, task := signedTask(t)
	task.Args["port"] = "22"
	result := validateTask(cfg, task)
	if result.OK || result.Message != "task signature verification failed" {
		t.Fatalf("tampered task was accepted: %+v", result)
	}
}

func signedTask(t *testing.T) (agentConfig, agentTask) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	task := agentTask{
		ID: "task-1", Name: "tcp_probe", TimeoutSeconds: 5, IssuedAt: time.Now().Unix(), Nonce: "nonce-1",
		Args: map[string]string{"host": "127.0.0.1", "port": "9443"},
	}
	canonical, _ := json.Marshal(task)
	task.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return agentConfig{TaskAllowlist: []string{"tcp_probe"}, TaskPublicKey: base64.StdEncoding.EncodeToString(publicKey)}, task
}
