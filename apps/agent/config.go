package main

import (
	"encoding/json"
	"errors"
	"os"
)

type agentConfig struct {
	NodeID              string   `json:"node_id"`
	CoreURL             string   `json:"core_url"`
	Listen              string   `json:"listen"`
	ServerCAFile        string   `json:"server_ca_file"`
	CertificateFile     string   `json:"certificate_file"`
	PrivateKeyFile      string   `json:"private_key_file"`
	EnrollmentTokenFile string   `json:"enrollment_token_file"`
	HeartbeatSeconds    int      `json:"heartbeat_seconds"`
	TaskPublicKey       string   `json:"task_public_key"`
	TaskAllowlist       []string `json:"task_allowlist"`
}

func defaultConfig(listen string) agentConfig {
	return agentConfig{
		Listen:           listen,
		HeartbeatSeconds: 30,
		TaskAllowlist: []string{
			"wireguard_status",
			"service_probe",
			"tcp_probe",
			"http_probe",
			"docker_list",
		},
	}
}

func loadConfig(path, listen string) (agentConfig, error) {
	cfg := defaultConfig(listen)
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Listen == "" {
		cfg.Listen = listen
	}
	if cfg.Listen == "" {
		return cfg, errors.New("listen address is required")
	}
	if len(cfg.TaskAllowlist) == 0 {
		cfg.TaskAllowlist = defaultConfig(listen).TaskAllowlist
	}
	if cfg.HeartbeatSeconds < 10 || cfg.HeartbeatSeconds > 300 {
		return cfg, errors.New("heartbeat_seconds must be 10-300")
	}
	if cfg.CoreURL != "" {
		if cfg.NodeID == "" || cfg.ServerCAFile == "" || cfg.CertificateFile == "" || cfg.PrivateKeyFile == "" {
			return cfg, errors.New("outbound reporting requires node_id, server_ca_file, certificate_file and private_key_file")
		}
	}
	return cfg, nil
}
