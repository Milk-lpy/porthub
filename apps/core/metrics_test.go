package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestCollectCoreMetrics(t *testing.T) {
	m := collectCoreMetrics()
	if m.Time.IsZero() {
		t.Error("expected non-zero time")
	}
	if m.MemoryTotalBytes == 0 {
		t.Error("expected non-zero memory total")
	}
	if m.MemoryUsedBytes > m.MemoryTotalBytes {
		t.Errorf("memory used %d > total %d", m.MemoryUsedBytes, m.MemoryTotalBytes)
	}
	if m.DiskTotalBytes == 0 {
		t.Error("expected non-zero disk total")
	}
	if m.DiskUsedBytes > m.DiskTotalBytes {
		t.Errorf("disk used %d > total %d", m.DiskUsedBytes, m.DiskTotalBytes)
	}
	if m.Processes <= 0 {
		t.Error("expected positive process count")
	}
}

func TestCollectCoreMetricsCPUSample(t *testing.T) {
	first := collectCoreMetrics()
	time.Sleep(1100 * time.Millisecond)
	second := collectCoreMetrics()
	// 第二次采样应算出 CPU 百分比 (0-100), 首次采样为 0 (无历史基线)
	if first.CPUPercent < 0 || first.CPUPercent > 100 {
		t.Errorf("first CPU percent out of range: %f", first.CPUPercent)
	}
	if second.CPUPercent < 0 || second.CPUPercent > 100 {
		t.Errorf("second CPU percent out of range: %f", second.CPUPercent)
	}
}

func TestCoreMetricsHandlerJSON(t *testing.T) {
	oldDB := db
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Exec("create table audit_log(id integer primary key, ts text, actor text, action text, detail text)"); err != nil {
		t.Fatal(err)
	}
	db = testDB
	defer func() { testDB.Close(); db = oldDB }()
	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	rec := httptest.NewRecorder()
	coreMetricsHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("content-type"); ct != "application/json; charset=utf-8" {
		t.Errorf("unexpected content-type: %s", ct)
	}
	var parsed CoreMetrics
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if parsed.Time.IsZero() || parsed.MemoryTotalBytes == 0 {
		t.Errorf("expected populated metrics, got %+v", parsed)
	}
}

func TestReadLoadAvg(t *testing.T) {
	load1, load5, load15 := readLoadAvg()
	if load1 < 0 || load5 < 0 || load15 < 0 {
		t.Errorf("negative load values: %f %f %f", load1, load5, load15)
	}
}

func TestIsNumericName(t *testing.T) {
	cases := map[string]bool{"123": true, "abc": false, "12a": false, "": false, "0": true}
	for input, want := range cases {
		if got := isNumericName(input); got != want {
			t.Errorf("isNumericName(%q) = %v, want %v", input, got, want)
		}
	}
}
