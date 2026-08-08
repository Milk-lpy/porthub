package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestNewAuditRecordAddsReadableContext(t *testing.T) {
	record := newAuditRecord(7, "2026-08-08T10:00:00Z", "boring14455", "port_forward_toggle", "id=12 enabled=false")
	if record.ID != 7 || record.ActionLabel != "切换端口转发" {
		t.Fatalf("unexpected identity fields: %+v", record)
	}
	if record.Category != "mapping" || record.CategoryLabel != "映射与入口" {
		t.Fatalf("unexpected category: %+v", record)
	}
	if record.Target != "转发 #12 · 已停用" || record.Result != "success" {
		t.Fatalf("unexpected target/result: %+v", record)
	}
	if record.Severity != "info" || record.SeverityLabel != "普通" {
		t.Fatalf("unexpected severity: %+v", record)
	}
}

func TestQueryAuditRecordsFiltersPresentationFields(t *testing.T) {
	oldDB := db
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		testDB.Close()
		db = oldDB
	}()
	db = testDB
	if _, err := db.Exec(`create table audit(ts text, actor text, action text, detail text)`); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		ts, actor, action, detail string
	}{
		{"2026-08-08T10:00:00Z", "system", "deploy_success", "42"},
		{"2026-08-08T10:01:00Z", "boring14455", "mapping_create", "饥荒服务器"},
		{"2026-08-08T10:02:00Z", "anonymous", "login_failed", "guest"},
	}
	for _, row := range rows {
		if _, err := db.Exec("insert into audit(ts,actor,action,detail) values(?,?,?,?)", row.ts, row.actor, row.action, row.detail); err != nil {
			t.Fatal(err)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/api/audit?category=mapping&q=%E9%A5%A5%E8%8D%92", nil)
	result, err := queryAuditRecords(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].ID == 0 || result[0].Target != "饥荒服务器" {
		t.Fatalf("filtered record is not readable: %+v", result)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/audit?severity=warning&from=2026-08-08&to=2026-08-08&limit=10", nil)
	result, err = queryAuditRecords(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].Action != "login_failed" || result[0].ResultLabel != "失败" {
		t.Fatalf("date/severity filter returned unexpected records: %+v", result)
	}
}
