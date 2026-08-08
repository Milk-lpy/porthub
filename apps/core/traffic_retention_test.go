package main

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestCleanupTrafficRetention(t *testing.T) {
	oldDB := db
	oldRetention := trafficRetentionDays
	defer func() {
		db = oldDB
		trafficRetentionDays = oldRetention
	}()
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range []string{
		`create table traffic_samples(id integer primary key, ts text, edge_version text, packets integer, bytes integer, raw_json text)`,
		`create table traffic_rule_samples(id integer primary key, sample_id integer, ts text, protocol text, port integer, target text, packets integer, bytes integer)`,
		`create table public_source_audits(id integer primary key, last_seen_at text)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	oldTS := now.Add(-40 * 24 * time.Hour).Format(time.RFC3339)
	newTS := now.Add(-2 * 24 * time.Hour).Format(time.RFC3339)
	db.Exec("insert into traffic_samples(id,ts,edge_version,packets,bytes,raw_json) values(1,?,?,?,?,?)", oldTS, "1", 1, 1, "{}")
	db.Exec("insert into traffic_samples(id,ts,edge_version,packets,bytes,raw_json) values(2,?,?,?,?,?)", newTS, "2", 2, 2, "{}")
	db.Exec("insert into traffic_rule_samples(sample_id,ts,protocol,port,target,packets,bytes) values(1,?,?,?,?,?,?)", oldTS, "tcp", 1, "10.0.0.1", 1, 1)
	db.Exec("insert into traffic_rule_samples(sample_id,ts,protocol,port,target,packets,bytes) values(2,?,?,?,?,?,?)", newTS, "tcp", 2, "10.0.0.2", 2, 2)
	trafficRetentionDays = 30
	if err := cleanupTrafficRetention(now); err != nil {
		t.Fatal(err)
	}
	var samples, rules int
	db.QueryRow("select count(*) from traffic_samples").Scan(&samples)
	db.QueryRow("select count(*) from traffic_rule_samples").Scan(&rules)
	if samples != 1 || rules != 1 {
		t.Fatalf("unexpected retention counts samples=%d rules=%d", samples, rules)
	}
}
