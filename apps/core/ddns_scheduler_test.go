package main

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestDDNSSchedulerSyncAndBackoff(t *testing.T) {
	oldDB, oldIP := db, edgePublicIPv4
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db, edgePublicIPv4 = testDB, "198.51.100.44"
	defer func() { testDB.Close(); db, edgePublicIPv4 = oldDB, oldIP }()
	for _, statement := range []string{
		`create table ddns_records(id integer primary key,name text,fqdn text,provider_id int,record_type text,ip_source text,last_value text,ttl int,enabled int,managed_by_lucky int,interval_seconds int,last_sync_at text,last_error text,failure_count int,created_at text,updated_at text,ip_urls text,net_interface text,ip_regex text,force_interval_seconds int,notify_webhook text,verify_dns int,manual_ip text)`,
		`create table ddns_providers(id integer primary key,name text,type text,config text,secret_ref text,enabled int,created_at text,updated_at text)`,
		`create table audit(ts text,actor text,action text,detail text)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	db.Exec(`insert into ddns_providers(id,name,type,config,enabled) values(1,'external','external','{}',1)`)
	db.Exec(`insert into ddns_records(id,name,fqdn,provider_id,record_type,ip_source,last_value,ttl,enabled,managed_by_lucky,interval_seconds) values(1,'edge','edge.example.test',1,'A','edge_public','',300,1,0,60)`)
	if err := runDueDDNSSyncs(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var value, synced string
	var failures int
	db.QueryRow("select last_value,last_sync_at,failure_count from ddns_records where id=1").Scan(&value, &synced, &failures)
	if value != "198.51.100.44" || synced == "" || failures != 0 {
		t.Fatalf("value=%q synced=%q failures=%d", value, synced, failures)
	}
	record := ddnsRecordItem{Interval: 60, FailureCount: 3, LastSyncAt: time.Now().UTC().Format(time.RFC3339)}
	if ddnsSyncDue(record, time.Now().UTC().Add(3*time.Minute)) {
		t.Fatal("retry backoff was not applied")
	}
	if !ddnsSyncDue(record, time.Now().UTC().Add(5*time.Minute)) {
		t.Fatal("record should be due after exponential backoff")
	}
}
