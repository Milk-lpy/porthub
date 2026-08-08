package main

import (
	"database/sql"
	"porthub/internal/snapshots"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestSnapshotHistoryAndStateRestore(t *testing.T) {
	oldDB := db
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db = testDB
	defer func() { db.Close(); db = oldDB }()
	for _, statement := range []string{
		`create table snapshot_history(id integer primary key, version integer unique, created_at text, operator text, sha256 text, status text, result text, source_version integer default 0, payload text)`,
		mappingTableDDL,
		`create table acl_rules(id integer primary key, name text, action text, cidr text, enabled int, protocols text, port_start int, port_end int, node_ids text, service_ids text, group_ids text, weekdays text, start_time text, end_time text, timezone text, created_at text, updated_at text)`,
		`create table ip_sets(id integer primary key, name text, kind text, action text, cidrs text, enabled int, created_at text, updated_at text)`,
		`create table http_proxies(id integer primary key, name text, host text, path text, target text, targets text, headers text, health_path text, load_balance text, enabled int, force_tls int, websocket int, preserve_host int, created_at text, updated_at text)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := snapshots.Snapshot{
		Version: 101, CreatedAt: time.Now().UTC(), Operator: "admin", SHA256: "sha",
		Mappings:    []snapshots.Mapping{{ID: "4", Name: "NAS", TargetIP: "192.0.2.50", PublicStart: 18080, PublicEnd: 18080, TargetStart: 80, TargetEnd: 80, Protocol: snapshots.TCP, Enabled: true, ACLIDs: []string{"7"}}},
		ACLRules:    []snapshots.ACLRule{{ID: "7", Name: "office", Action: snapshots.ACLAllow, CIDR: "192.0.2.0/24", Enabled: true}},
		IPSets:      []snapshots.IPSet{{ID: "8", Name: "blocked", Kind: "custom", Action: snapshots.ACLDeny, CIDRs: []string{"198.51.100.0/24"}, Enabled: true}},
		HTTPProxies: []snapshots.HTTPProxy{{ID: "9", Name: "web", Host: "nas.example.test", Path: "/", Target: "http://192.0.2.50", Enabled: true}},
	}
	if err := recordSnapshot(snapshot, "applied", "ok", 0); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadHistoricalSnapshot(101)
	if err != nil || loaded.Mappings[0].Name != "NAS" {
		t.Fatalf("load failed: %+v %v", loaded, err)
	}
	if err := restoreSnapshotState(loaded); err != nil {
		t.Fatal(err)
	}
	var mappingID, aclID, proxyID int
	db.QueryRow("select id from mappings").Scan(&mappingID)
	db.QueryRow("select id from acl_rules").Scan(&aclID)
	db.QueryRow("select id from http_proxies").Scan(&proxyID)
	if mappingID != 4 || aclID != 7 || proxyID != 9 {
		t.Fatalf("ids were not preserved: mapping=%d acl=%d proxy=%d", mappingID, aclID, proxyID)
	}
}
