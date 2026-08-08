package main

import (
	"database/sql"
	"net/http/httptest"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestReconcileSystemAlertsDeduplicatesAndResolves(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()
	if _, err := testDB.Exec(`create table system_alerts(id integer primary key, fingerprint text unique, severity text, source text, title text, detail text, first_seen_at text, last_seen_at text, active int default 1, acknowledged_at text, resolved_at text)`); err != nil {
		t.Fatal(err)
	}
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()
	metric := map[string]any{"alerts": []any{map[string]any{"fingerprint": "edge:memory", "severity": "warning", "title": "Memory", "detail": "86%"}}}
	reconcileSystemAlerts(metric)
	reconcileSystemAlerts(metric)
	var count, active int
	if err := db.QueryRow("select count(*),max(active) from system_alerts").Scan(&count, &active); err != nil || count != 1 || active != 1 {
		t.Fatalf("alert was not deduplicated: count=%d active=%d err=%v", count, active, err)
	}
	reconcileSystemAlerts(map[string]any{"alerts": []any{}})
	if err := db.QueryRow("select active from system_alerts where fingerprint='edge:memory'").Scan(&active); err != nil || active != 0 {
		t.Fatalf("alert was not resolved: active=%d err=%v", active, err)
	}
	reconcileSystemAlerts(metric)
	if err := db.QueryRow("select active from system_alerts where fingerprint='edge:memory'").Scan(&active); err != nil || active != 1 {
		t.Fatalf("alert was not reactivated: active=%d err=%v", active, err)
	}
}

func TestMonitorWebSocketOriginIsSameHost(t *testing.T) {
	request := httptest.NewRequest("GET", "https://porthub.test/api/monitor/stream", nil)
	request.Host = "porthub.test"
	request.Header.Set("Origin", "https://porthub.test")
	if !monitorUpgrader.CheckOrigin(request) {
		t.Fatal("same-origin websocket rejected")
	}
	request.Header.Set("Origin", "https://attacker.test")
	if monitorUpgrader.CheckOrigin(request) {
		t.Fatal("cross-origin websocket accepted")
	}
}

func TestOperatorMayAcknowledgeAlert(t *testing.T) {
	if !roleAllowed("operator", "POST", "/api/alerts") {
		t.Fatal("operator should be allowed to acknowledge alerts")
	}
}
