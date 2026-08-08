package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

const localAgentURL = "http://127.0.0.1:9731"

func nodeStatus(w http.ResponseWriter, r *http.Request) {
	nodes := []map[string]any{}
	status, err := localAgentJSON("/api/agent/status")
	if err != nil {
		nodes = append(nodes, map[string]any{
			"name":    "core-local-agent",
			"node_id": "core-local-agent",
			"role":    "core",
			"online":  false,
			"error":   err.Error(),
		})
	} else {
		status["name"] = "core-local-agent"
		status["node_id"] = "core-local-agent"
		status["role"] = "core"
		status["online"] = true
		nodes = append(nodes, status)
	}
	rows, queryErr := db.Query("select node_id,name,os,arch,version,address,status_json,last_seen_at,certificate_expires_at,enabled from agent_nodes order by node_id")
	if queryErr == nil {
		defer rows.Close()
		for rows.Next() {
			var nodeID, name, osName, arch, version, address, statusJSON, lastSeen, certExpires string
			var enabled int
			if rows.Scan(&nodeID, &name, &osName, &arch, &version, &address, &statusJSON, &lastSeen, &certExpires, &enabled) != nil {
				continue
			}
			node := map[string]any{}
			json.Unmarshal([]byte(statusJSON), &node)
			seen, _ := time.Parse(time.RFC3339, lastSeen)
			node["node_id"] = nodeID
			node["name"] = name
			node["os"] = osName
			node["arch"] = arch
			node["version"] = version
			node["address"] = address
			node["role"] = "agent"
			node["last_seen_at"] = lastSeen
			node["certificate_expires_at"] = certExpires
			node["online"] = enabled == 1 && time.Since(seen) <= 90*time.Second
			nodes = append(nodes, node)
		}
	}
	writeJSON(w, nodes)
}

func nodeDiscovery(w http.ResponseWriter, r *http.Request) {
	if nodeID := r.URL.Query().Get("node_id"); nodeID != "" && nodeID != "core-local-agent" {
		var discovery string
		if err := db.QueryRow("select discovery_json from agent_nodes where node_id=? and enabled=1", nodeID).Scan(&discovery); err != nil {
			http.Error(w, "node not found", http.StatusNotFound)
			return
		}
		var payload map[string]any
		if json.Unmarshal([]byte(discovery), &payload) != nil {
			http.Error(w, "node discovery unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, payload)
		return
	}
	discovery, err := localAgentJSON("/api/agent/discovery")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, discovery)
}

func localAgentJSON(path string) (map[string]any, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(localAgentURL + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, errors.New(string(data))
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}
