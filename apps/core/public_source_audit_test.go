package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestNormalizePublicSourceIP(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{name: "public ipv4", input: "198.51.100.22", want: "198.51.100.22", ok: true},
		{name: "public ipv6", input: "2001:db8::22", want: "2001:db8::22", ok: true},
		{name: "private ipv4", input: "10.20.30.22", ok: false},
		{name: "carrier nat", input: "100.64.1.22", ok: false},
		{name: "loopback", input: "127.0.0.1", ok: false},
		{name: "private ipv6", input: "fd00::22", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := normalizePublicSourceIP(tc.input)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("normalizePublicSourceIP(%q) = %q, %v; want %q, %v", tc.input, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestStorePublicSourceAuditsBucketsAndFiltersPrivate(t *testing.T) {
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
	for _, statement := range []string{
		`create table public_source_audits(id integer primary key, observed_minute text not null, first_seen_at text not null, last_seen_at text not null, edge_version text, source_ip text not null, mapping_id text, mapping text, protocol text, public_port integer, target text, state text, bytes integer default 0, observations integer default 1, timeout_seconds integer default 0)`,
		`create unique index uq_public_source_audits_bucket on public_source_audits(observed_minute,source_ip,mapping_id,protocol,public_port)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}

	observed := "2026-08-08T12:34:56Z"
	metrics := map[string]any{"connection_summary": []any{
		map[string]any{"observed_at": observed, "source_ip": "198.51.100.22", "mapping_id": "minecraft", "mapping": "Minecraft", "protocol": "tcp", "public_port": float64(25565), "target": "10.255.0.2:25565", "state": "ESTABLISHED", "bytes": float64(800), "timeout_seconds": float64(120)},
		map[string]any{"observed_at": observed, "source_ip": "10.20.30.22", "mapping_id": "internal", "mapping": "Internal", "protocol": "tcp", "public_port": float64(22), "target": "10.255.0.2:22", "bytes": float64(900), "timeout_seconds": float64(60)},
	}}
	if err := storePublicSourceAudits("v1", metrics); err != nil {
		t.Fatal(err)
	}
	metrics["connection_summary"].([]any)[0].(map[string]any)["bytes"] = float64(1200)
	if err := storePublicSourceAudits("v2", metrics); err != nil {
		t.Fatal(err)
	}

	var count, observations int
	var bytes uint64
	if err := db.QueryRow("select count(*) from public_source_audits").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("select observations,bytes from public_source_audits").Scan(&observations, &bytes); err != nil {
		t.Fatal(err)
	}
	if count != 1 || observations != 2 || bytes != 1200 {
		t.Fatalf("unexpected audit bucket count=%d observations=%d bytes=%d", count, observations, bytes)
	}
}

func TestTrafficPublicSourcesRedactsReadonlyAndReturnsExactForOperator(t *testing.T) {
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
	for _, statement := range []string{
		`create table public_source_audits(id integer primary key, observed_minute text not null, first_seen_at text not null, last_seen_at text not null, edge_version text, source_ip text not null, mapping_id text, mapping text, protocol text, public_port integer, target text, state text, bytes integer default 0, observations integer default 1, timeout_seconds integer default 0)`,
		`create unique index uq_public_source_audits_bucket on public_source_audits(observed_minute,source_ip,mapping_id,protocol,public_port)`,
		`insert into public_source_audits(observed_minute,first_seen_at,last_seen_at,edge_version,source_ip,mapping_id,mapping,protocol,public_port,target,state,bytes,observations,timeout_seconds) values('2026-08-08T12:34:00Z','2026-08-08T12:34:56Z','2026-08-08T12:35:56Z','v1','198.51.100.22','minecraft','Minecraft','tcp',25565,'10.255.0.2:25565','ESTABLISHED',1200,2,120)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}

	request := func(role string) publicSourceAuditResponse {
		req := httptest.NewRequest(http.MethodGet, "/api/traffic/public-sources?limit=10", nil)
		ctx := context.WithValue(req.Context(), roleKey, role)
		rec := httptest.NewRecorder()
		trafficPublicSources(rec, req.WithContext(ctx))
		if rec.Code != http.StatusOK {
			t.Fatalf("role %s: expected 200, got %d: %s", role, rec.Code, rec.Body.String())
		}
		var response publicSourceAuditResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}

	readonly := request("readonly")
	if readonly.ExactSourceIP || len(readonly.Records) != 1 || readonly.Records[0].SourceIP != "198.51.xxx.xxx" {
		t.Fatalf("readonly source exposure is wrong: %+v", readonly)
	}
	operator := request("operator")
	if !operator.ExactSourceIP || len(operator.Records) != 1 || operator.Records[0].SourceIP != "198.51.100.22" {
		t.Fatalf("operator source exposure is wrong: %+v", operator)
	}
}

func TestParseSourceAuditTime(t *testing.T) {
	if got := parseSourceAuditTime("2026-08-08T12:34:56.123Z"); got.IsZero() {
		t.Fatal("expected RFC3339Nano timestamp")
	}
	if got := parseSourceAuditTime("not-a-time"); !got.IsZero() {
		t.Fatal("expected invalid timestamp to be ignored")
	}
}
