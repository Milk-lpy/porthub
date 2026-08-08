package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestMappingImportRejectsDuplicatePublicPort(t *testing.T) {
	restore := testMappingDB(t)
	defer restore()
	insertTestMapping(t, "one", 18080, true)

	body := []byte(`{"mappings":[{"Name":"dup","Protocol":"tcp","PublicStart":18080,"TargetIP":"10.255.0.2","TargetStart":8081,"Enabled":true}]}`)
	res := httptest.NewRecorder()
	mappingImport(res, httptest.NewRequest(http.MethodPost, "/api/mappings/import", bytes.NewReader(body)))
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected duplicate rejection, got %d body=%s", res.Code, res.Body.String())
	}
}

func TestMappingBulkEnableValidatesConflictsBeforeWrite(t *testing.T) {
	restore := testMappingDB(t)
	defer restore()
	insertTestMapping(t, "active", 18080, true)
	insertTestMapping(t, "disabled-dup", 18080, false)

	body := []byte(`{"action":"enable","ids":["2"]}`)
	res := httptest.NewRecorder()
	mappingBulk(res, httptest.NewRequest(http.MethodPost, "/api/mappings/bulk", bytes.NewReader(body)))
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected conflict rejection, got %d body=%s", res.Code, res.Body.String())
	}
	var enabled int
	if err := db.QueryRow("select enabled from mappings where id=2").Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatal("conflicting mapping should remain disabled")
	}
}

func TestMappingExportReturnsMappings(t *testing.T) {
	restore := testMappingDB(t)
	defer restore()
	insertTestMapping(t, "one", 18080, true)

	res := httptest.NewRecorder()
	mappingExport(res, httptest.NewRequest(http.MethodGet, "/api/mappings/export", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("unexpected status %d", res.Code)
	}
	var out struct {
		Mappings []map[string]any `json:"mappings"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Mappings) != 1 || out.Mappings[0]["Name"] != "one" {
		t.Fatalf("unexpected export: %+v", out)
	}
}

func testMappingDB(t *testing.T) func() {
	t.Helper()
	oldDB := db
	nextDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db = nextDB
	for _, stmt := range []string{
		mappingTableDDL,
		`create table audit(ts text, actor text, action text, detail text)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	return func() {
		db.Close()
		db = oldDB
	}
}

func insertTestMapping(t *testing.T, name string, publicPort int, enabled bool) {
	t.Helper()
	_, err := db.Exec("insert into mappings(name,target_ip,public_start,public_end,target_start,target_end,proto,enabled,acl_ids) values(?,?,?,?,?,?,?,?,?)", name, "10.255.0.2", publicPort, publicPort, 8080, 8080, "tcp", boolInt(enabled), "[]")
	if err != nil {
		t.Fatal(err)
	}
}
