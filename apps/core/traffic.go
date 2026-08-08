package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"
)

type trafficSample struct {
	ID          int     `json:"id"`
	TS          string  `json:"ts"`
	EdgeVersion string  `json:"edge_version"`
	Packets     uint64  `json:"packets"`
	Bytes       uint64  `json:"bytes"`
	RawJSON     string  `json:"raw_json,omitempty"`
	RXBytes     uint64  `json:"rx_bytes"`
	TXBytes     uint64  `json:"tx_bytes"`
	RXBPS       uint64  `json:"rx_bytes_per_second"`
	TXBPS       uint64  `json:"tx_bytes_per_second"`
	Connections int     `json:"connections"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryUsed  uint64  `json:"memory_used_bytes"`
	MemoryTotal uint64  `json:"memory_total_bytes"`
}

type trafficRuleSample struct {
	ID       int    `json:"id"`
	SampleID int    `json:"sample_id"`
	TS       string `json:"ts"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Target   string `json:"target"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
}

func trafficCollector(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if _, err := collectTrafficSample(); err != nil {
			log.Println("traffic collector:", err)
			setControlAlert("control:edge-offline", "critical", "Edge 监控不可达", "Core 无法通过管理隧道读取 Edge 指标", true)
		} else {
			setControlAlert("control:edge-offline", "critical", "Edge 监控不可达", "", false)
		}
		reconcileNodeHealthAlerts(time.Now())
		if err := cleanupTrafficRetention(time.Now()); err != nil {
			log.Println("traffic retention:", err)
		}
	}
}

func trafficSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sample, err := collectTrafficSample()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	audit(actor(r), "traffic_sample_collect", sample.EdgeVersion)
	writeJSON(w, sample)
}

func trafficRecent(w http.ResponseWriter, r *http.Request) {
	limit := boundedLimit(r, 120)
	rows, _ := db.Query("select id,ts,edge_version,packets,bytes,raw_json,coalesce(rx_bytes,0),coalesce(tx_bytes,0),coalesce(rx_bps,0),coalesce(tx_bps,0),coalesce(connections,0),coalesce(cpu_percent,0),coalesce(memory_used,0),coalesce(memory_total,0) from traffic_samples order by id desc limit ?", limit)
	defer rows.Close()
	var out []trafficSample
	exact := canViewExactSourceIP(r)
	for rows.Next() {
		sample := scanTrafficSample(rows)
		sample.RawJSON = redactTrafficRawJSON(sample.RawJSON, exact)
		out = append(out, sample)
	}
	writeJSON(w, out)
}

func trafficRulesRecent(w http.ResponseWriter, r *http.Request) {
	limit := boundedLimit(r, 120)
	rows, _ := db.Query("select id,sample_id,ts,protocol,port,target,packets,bytes from traffic_rule_samples order by id desc limit ?", limit)
	defer rows.Close()
	var out []trafficRuleSample
	for rows.Next() {
		var s trafficRuleSample
		rows.Scan(&s.ID, &s.SampleID, &s.TS, &s.Protocol, &s.Port, &s.Target, &s.Packets, &s.Bytes)
		out = append(out, s)
	}
	writeJSON(w, out)
}

func trafficRank(w http.ResponseWriter, r *http.Request) {
	limit := boundedLimit(r, 20)
	var sampleID int
	if err := db.QueryRow("select id from traffic_samples order by id desc limit 1").Scan(&sampleID); err != nil {
		writeJSON(w, []trafficRuleSample{})
		return
	}
	rows, _ := db.Query("select id,sample_id,ts,protocol,port,target,packets,bytes from traffic_rule_samples where sample_id=? order by bytes desc, packets desc limit ?", sampleID, limit)
	defer rows.Close()
	var out []trafficRuleSample
	for rows.Next() {
		var s trafficRuleSample
		rows.Scan(&s.ID, &s.SampleID, &s.TS, &s.Protocol, &s.Port, &s.Target, &s.Packets, &s.Bytes)
		out = append(out, s)
	}
	writeJSON(w, out)
}

func trafficTrend(w http.ResponseWriter, r *http.Request) {
	proto := r.URL.Query().Get("protocol")
	port, err := strconv.Atoi(r.URL.Query().Get("port"))
	if proto == "" || err != nil || port < 1 || port > 65535 {
		http.Error(w, "protocol and valid port required", http.StatusBadRequest)
		return
	}
	limit := boundedLimit(r, 120)
	rows, _ := db.Query("select id,sample_id,ts,protocol,port,target,packets,bytes from traffic_rule_samples where protocol=? and port=? order by id desc limit ?", proto, port, limit)
	defer rows.Close()
	var out []trafficRuleSample
	for rows.Next() {
		var s trafficRuleSample
		rows.Scan(&s.ID, &s.SampleID, &s.TS, &s.Protocol, &s.Port, &s.Target, &s.Packets, &s.Bytes)
		out = append(out, s)
	}
	writeJSON(w, out)
}

func collectTrafficSample() (trafficSample, error) {
	metrics, err := getEdgeJSON("/api/metrics")
	if err != nil {
		return trafficSample{}, err
	}
	raw, _ := json.Marshal(metrics)
	sample := trafficSample{
		TS:          time.Now().Format(time.RFC3339),
		EdgeVersion: jsonValueString(metrics["version"]),
		Packets:     jsonValueUint(metrics["packets"]),
		Bytes:       jsonValueUint(metrics["bytes"]),
		RawJSON:     string(raw),
		RXBytes:     jsonValueUint(metrics["rx_bytes"]),
		TXBytes:     jsonValueUint(metrics["tx_bytes"]),
		RXBPS:       jsonValueUint(metrics["rx_bytes_per_second"]),
		TXBPS:       jsonValueUint(metrics["tx_bytes_per_second"]),
		Connections: int(jsonValueUint(metrics["connections"])),
		CPUPercent:  jsonValueFloat(metrics["cpu_percent"]),
		MemoryUsed:  jsonValueUint(metrics["memory_used_bytes"]),
		MemoryTotal: jsonValueUint(metrics["memory_total_bytes"]),
	}
	res, err := db.Exec(`insert into traffic_samples(ts,edge_version,packets,bytes,raw_json,rx_bytes,tx_bytes,rx_bps,tx_bps,connections,cpu_percent,memory_used,memory_total) values(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		sample.TS, sample.EdgeVersion, sample.Packets, sample.Bytes, sample.RawJSON, sample.RXBytes, sample.TXBytes, sample.RXBPS, sample.TXBPS, sample.Connections, sample.CPUPercent, sample.MemoryUsed, sample.MemoryTotal)
	if err != nil {
		return trafficSample{}, err
	}
	id, _ := res.LastInsertId()
	sample.ID = int(id)
	storeTrafficRuleSamples(sample, metrics)
	if err := storePublicSourceAudits(sample.EdgeVersion, metrics); err != nil {
		return trafficSample{}, err
	}
	reconcileSystemAlerts(metrics)
	return sample, nil
}

func storeTrafficRuleSamples(sample trafficSample, metrics map[string]any) {
	rules, ok := metrics["rules"].([]any)
	if !ok {
		return
	}
	tx, err := db.Begin()
	if err != nil {
		return
	}
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tx.Exec(
			"insert into traffic_rule_samples(sample_id,ts,protocol,port,target,packets,bytes) values(?,?,?,?,?,?,?)",
			sample.ID,
			sample.TS,
			jsonValueString(rule["protocol"]),
			int(jsonValueUint(rule["port"])),
			jsonValueString(rule["target"]),
			jsonValueUint(rule["packets"]),
			jsonValueUint(rule["bytes"]),
		)
	}
	tx.Commit()
}

func cleanupTrafficRetention(now time.Time) error {
	if trafficRetentionDays <= 0 {
		return nil
	}
	cutoff := now.Add(-time.Duration(trafficRetentionDays) * 24 * time.Hour).Format(time.RFC3339)
	if _, err := db.Exec("delete from traffic_rule_samples where ts < ?", cutoff); err != nil {
		return err
	}
	if _, err := db.Exec("delete from traffic_samples where ts < ?", cutoff); err != nil {
		return err
	}
	_, err := db.Exec("delete from public_source_audits where last_seen_at < ?", cutoff)
	return err
}

func scanTrafficSample(rows *sql.Rows) trafficSample {
	var s trafficSample
	rows.Scan(&s.ID, &s.TS, &s.EdgeVersion, &s.Packets, &s.Bytes, &s.RawJSON, &s.RXBytes, &s.TXBytes, &s.RXBPS, &s.TXBPS, &s.Connections, &s.CPUPercent, &s.MemoryUsed, &s.MemoryTotal)
	return s
}

func jsonValueFloat(v any) float64 {
	switch value := v.(type) {
	case json.Number:
		result, _ := strconv.ParseFloat(value.String(), 64)
		return result
	case float64:
		return value
	default:
		return 0
	}
}

func jsonValueString(v any) string {
	switch x := v.(type) {
	case json.Number:
		return x.String()
	case string:
		return x
	case float64:
		return strconv.FormatInt(int64(x), 10)
	default:
		return ""
	}
}

func jsonValueUint(v any) uint64 {
	switch x := v.(type) {
	case json.Number:
		n, _ := strconv.ParseUint(x.String(), 10, 64)
		return n
	case float64:
		return uint64(x)
	case int:
		return uint64(x)
	case uint64:
		return x
	default:
		return 0
	}
}

func boundedLimit(r *http.Request, fallback int) int {
	limit := fallback
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	return limit
}
