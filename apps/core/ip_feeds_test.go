package main

import (
	"database/sql"
	"io"
	"net/http"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func TestNormalizeIPFeedRejectsSSRFAndBadHash(t *testing.T) {
	items := []ipFeedItem{
		{Name: "private", Kind: "geoip", Action: "deny", URL: "https://127.0.0.1/feed", RefreshHours: 24},
		{Name: "plain", Kind: "geoip", Action: "deny", URL: "http://example.com/feed", RefreshHours: 24},
		{Name: "hash", Kind: "asn", Action: "deny", URL: "https://example.com/feed", ExpectedSHA256: "bad", RefreshHours: 24},
	}
	for _, item := range items {
		if err := normalizeIPFeed(&item); err == nil {
			t.Fatalf("unsafe feed accepted: %+v", item)
		}
	}
}

func TestSyncIPFeedCreatesManagedIPSet(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()
	for _, statement := range []string{
		`create table ip_feeds(id integer primary key,name text,kind text,action text,url text,expected_sha256 text,refresh_hours int,enabled int,ip_set_id int,last_fetch_at text,last_sha256 text,last_error text,created_at text,updated_at text)`,
		`create table ip_sets(id integer primary key,name text,kind text,action text,cidrs text,enabled int,created_at text,updated_at text)`,
	} {
		if _, err := testDB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := testDB.Exec(`insert into ip_feeds(id,name,kind,action,url,refresh_hours,enabled,ip_set_id) values(1,'CN test','geoip','deny','https://feed.example/cn.txt',24,1,0)`); err != nil {
		t.Fatal(err)
	}
	oldDB, oldFactory := db, ipFeedClientFactory
	db = testDB
	ipFeedClientFactory = func(string) (*http.Client, error) {
		return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			body := "203.0.113.0/24\n2001:db8::/32\n"
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}, nil
	}
	defer func() { db, ipFeedClientFactory = oldDB, oldFactory }()
	result, err := syncIPFeed(1, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != 2 || result.IPSetID < 1 || len(result.SHA256) != 64 {
		t.Fatalf("unexpected result: %+v", result)
	}
	var count int
	if err := db.QueryRow("select count(*) from ip_sets where id=? and kind='geoip'", result.IPSetID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("managed IP set missing count=%d err=%v", count, err)
	}
}
