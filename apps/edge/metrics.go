package main

import (
	"encoding/json"
	"net/http"
	"porthub/internal/snapshots"
	"strconv"
	"strings"
	"time"
)

type ruleCounter struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
	Target   string `json:"target,omitempty"`
}

type edgeMetrics struct {
	Time              time.Time           `json:"time"`
	Version           int64               `json:"version"`
	Rules             []ruleCounter       `json:"rules"`
	Packets           uint64              `json:"packets"`
	Bytes             uint64              `json:"bytes"`
	PublicInterface   string              `json:"public_interface"`
	RXBytes           uint64              `json:"rx_bytes"`
	TXBytes           uint64              `json:"tx_bytes"`
	RXBytesPerSecond  uint64              `json:"rx_bytes_per_second"`
	TXBytesPerSecond  uint64              `json:"tx_bytes_per_second"`
	CPUPercent        float64             `json:"cpu_percent"`
	MemoryUsedBytes   uint64              `json:"memory_used_bytes"`
	MemoryTotalBytes  uint64              `json:"memory_total_bytes"`
	DiskUsedBytes     uint64              `json:"disk_used_bytes"`
	DiskTotalBytes    uint64              `json:"disk_total_bytes"`
	Load1             float64             `json:"load_1"`
	Connections       int                 `json:"connections"`
	ConntrackMax      int                 `json:"conntrack_max"`
	ConnectionSummary []connectionSummary `json:"connection_summary"`
	Alerts            []metricAlert       `json:"alerts"`
	RuleText          string              `json:"rule_text,omitempty"`
}

func collectMetrics() (edgeMetrics, error) {
	out, err := edgeNetdListNFT()
	if err != nil {
		return edgeMetrics{Time: time.Now(), Version: last, RuleText: string(out)}, err
	}
	m := edgeMetrics{Time: time.Now(), Version: last}
	for _, line := range strings.Split(string(out), "\n") {
		rc, ok := parseCounterLine(line)
		if !ok {
			continue
		}
		m.Rules = append(m.Rules, rc)
		m.Packets += rc.Packets
		m.Bytes += rc.Bytes
	}
	system := collectEdgeSystemMetrics()
	m.PublicInterface = system.PublicInterface
	m.RXBytes, m.TXBytes = system.RXBytes, system.TXBytes
	m.RXBytesPerSecond, m.TXBytesPerSecond = system.RXBytesPerSecond, system.TXBytesPerSecond
	m.CPUPercent = system.CPUPercent
	m.MemoryUsedBytes, m.MemoryTotalBytes = system.MemoryUsedBytes, system.MemoryTotalBytes
	m.DiskUsedBytes, m.DiskTotalBytes = system.DiskUsedBytes, system.DiskTotalBytes
	m.Load1, m.Connections, m.ConntrackMax = system.Load1, system.Connections, system.ConntrackMax
	m.Alerts = system.Alerts
	mu.Lock()
	mappings := append([]snapshots.Mapping(nil), current.Mappings...)
	mu.Unlock()
	m.ConnectionSummary = collectConnectionSummary(mappings, 100)
	return m, nil
}

func parseCounterLine(line string) (ruleCounter, bool) {
	fields := strings.Fields(line)
	if len(fields) < 8 {
		return ruleCounter{}, false
	}
	protocolIndex := -1
	for index := 0; index+2 < len(fields); index++ {
		if (fields[index] == "tcp" || fields[index] == "udp") && fields[index+1] == "dport" {
			protocolIndex = index
			break
		}
	}
	if protocolIndex < 0 {
		return ruleCounter{}, false
	}
	port, err := strconv.Atoi(fields[protocolIndex+2])
	if err != nil {
		return ruleCounter{}, false
	}
	var packets, bytes uint64
	var target string
	for i := 3; i < len(fields); i++ {
		if fields[i] == "packets" && i+1 < len(fields) {
			packets, _ = strconv.ParseUint(fields[i+1], 10, 64)
		}
		if fields[i] == "bytes" && i+1 < len(fields) {
			bytes, _ = strconv.ParseUint(fields[i+1], 10, 64)
		}
		if fields[i] == "to" && i+1 < len(fields) {
			target = fields[i+1]
		}
	}
	if target == "" {
		return ruleCounter{}, false
	}
	return ruleCounter{Protocol: fields[protocolIndex], Port: port, Packets: packets, Bytes: bytes, Target: target}, true
}

func metrics(w http.ResponseWriter, r *http.Request) {
	m, err := collectMetrics()
	if err != nil {
		w.WriteHeader(503)
	}
	w.Header().Set("content-type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(m)
}
