package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

type systemAlert struct {
	ID             int    `json:"id"`
	Fingerprint    string `json:"fingerprint"`
	Severity       string `json:"severity"`
	Source         string `json:"source"`
	Title          string `json:"title"`
	Detail         string `json:"detail"`
	FirstSeenAt    string `json:"first_seen_at"`
	LastSeenAt     string `json:"last_seen_at"`
	Active         bool   `json:"active"`
	AcknowledgedAt string `json:"acknowledged_at,omitempty"`
	ResolvedAt     string `json:"resolved_at,omitempty"`
}

func systemAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var request struct {
			ID int `json:"id"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.ID < 1 {
			http.Error(w, "alert id required", http.StatusBadRequest)
			return
		}
		result, err := db.Exec("update system_alerts set acknowledged_at=? where id=?", time.Now().UTC().Format(time.RFC3339), request.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			http.Error(w, "alert not found", http.StatusNotFound)
			return
		}
		audit(actor(r), "alert_acknowledge", strconv.Itoa(request.ID))
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, loadSystemAlerts(boundedLimit(r, 50)))
}

func loadSystemAlerts(limit int) []systemAlert {
	rows, err := db.Query(`select id,fingerprint,severity,source,title,detail,first_seen_at,last_seen_at,active,coalesce(acknowledged_at,''),coalesce(resolved_at,'') from system_alerts order by active desc,last_seen_at desc limit ?`, limit)
	if err != nil {
		return []systemAlert{}
	}
	defer rows.Close()
	alerts := []systemAlert{}
	for rows.Next() {
		var alert systemAlert
		var active int
		if rows.Scan(&alert.ID, &alert.Fingerprint, &alert.Severity, &alert.Source, &alert.Title, &alert.Detail, &alert.FirstSeenAt, &alert.LastSeenAt, &active, &alert.AcknowledgedAt, &alert.ResolvedAt) == nil {
			alert.Active = active == 1
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

func reconcileSystemAlerts(metrics map[string]any) {
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	_, _ = tx.Exec("update system_alerts set active=0,resolved_at=? where source='edge' and active=1", now)
	items, _ := metrics["alerts"].([]any)
	for _, item := range items {
		value, ok := item.(map[string]any)
		if !ok {
			continue
		}
		fingerprint := jsonValueString(value["fingerprint"])
		severity := jsonValueString(value["severity"])
		title := jsonValueString(value["title"])
		detail := jsonValueString(value["detail"])
		if fingerprint == "" || title == "" || (severity != "warning" && severity != "critical") {
			continue
		}
		_, _ = tx.Exec(`insert into system_alerts(fingerprint,severity,source,title,detail,first_seen_at,last_seen_at,active,resolved_at) values(?,?,?,?,?,?,?,1,'')
			on conflict(fingerprint) do update set severity=excluded.severity,title=excluded.title,detail=excluded.detail,last_seen_at=excluded.last_seen_at,active=1,resolved_at=''`,
			fingerprint, severity, "edge", title, detail, now, now)
	}
	_ = tx.Commit()
}

func setControlAlert(fingerprint, severity, title, detail string, active bool) {
	now := time.Now().UTC().Format(time.RFC3339)
	if !active {
		_, _ = db.Exec("update system_alerts set active=0,resolved_at=? where fingerprint=? and active=1", now, fingerprint)
		return
	}
	_, _ = db.Exec(`insert into system_alerts(fingerprint,severity,source,title,detail,first_seen_at,last_seen_at,active,resolved_at) values(?,?,?,?,?,?,?,1,'')
		on conflict(fingerprint) do update set severity=excluded.severity,title=excluded.title,detail=excluded.detail,last_seen_at=excluded.last_seen_at,active=1,resolved_at=''`,
		fingerprint, severity, "control", title, detail, now, now)
}

func reconcileNodeHealthAlerts(now time.Time) {
	if _, err := localAgentJSON("/api/agent/status"); err != nil {
		setControlAlert("agent:core-local-agent", "warning", "Core 本机 Agent 异常", "无法读取本机节点状态", true)
	} else {
		setControlAlert("agent:core-local-agent", "warning", "Core 本机 Agent 异常", "", false)
	}
	rows, err := db.Query("select node_id,name,last_seen_at from agent_nodes where enabled=1")
	if err != nil {
		return
	}
	type nodeHeartbeat struct{ nodeID, name, lastSeen string }
	nodes := []nodeHeartbeat{}
	for rows.Next() {
		var node nodeHeartbeat
		if rows.Scan(&node.nodeID, &node.name, &node.lastSeen) == nil {
			nodes = append(nodes, node)
		}
	}
	rows.Close()
	seen := map[string]bool{}
	for _, node := range nodes {
		fingerprint := "agent:" + node.nodeID
		seen[fingerprint] = true
		observed, _ := time.Parse(time.RFC3339, node.lastSeen)
		if observed.IsZero() || now.Sub(observed) > 90*time.Second {
			setControlAlert(fingerprint, "warning", "Agent 节点离线", node.name+" 已超过 90 秒没有心跳", true)
		} else {
			setControlAlert(fingerprint, "warning", "Agent 节点离线", "", false)
		}
	}
	alertRows, err := db.Query("select fingerprint from system_alerts where source='control' and fingerprint like 'agent:%' and active=1")
	if err != nil {
		return
	}
	stale := []string{}
	for alertRows.Next() {
		var fingerprint string
		if alertRows.Scan(&fingerprint) == nil && fingerprint != "agent:core-local-agent" && !seen[fingerprint] {
			stale = append(stale, fingerprint)
		}
	}
	alertRows.Close()
	for _, fingerprint := range stale {
		setControlAlert(fingerprint, "warning", "Agent 节点离线", "", false)
	}
}

var monitorUpgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Scheme == "https" && parsed.Host == r.Host
}}

func monitorStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	connection, err := monitorUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer connection.Close()
	connection.SetWriteDeadline(time.Now().Add(5 * time.Second))
	exact := canViewExactSourceIP(r)
	if err := writeMonitorFrame(connection, exact); err != nil {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		connection.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := writeMonitorFrame(connection, exact); err != nil {
			return
		}
	}
}

func writeMonitorFrame(connection *websocket.Conn, exactSourceIP bool) error {
	metrics, err := getEdgeJSON("/api/metrics")
	if err != nil {
		return connection.WriteJSON(map[string]any{"type": "edge_offline", "time": time.Now().UTC(), "error": "Edge metrics unavailable"})
	}
	return connection.WriteJSON(map[string]any{"type": "metrics", "time": time.Now().UTC(), "metrics": redactMetricsSourceIPs(metrics, exactSourceIP), "alerts": loadSystemAlerts(10)})
}
