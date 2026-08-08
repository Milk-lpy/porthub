package main

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestGenericDuplicateDetectionForScannedItems(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()
	if _, err := testDB.Exec(`create table resources(id integer primary key, data text)`); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Exec(`create table services(id integer primary key, data text)`); err != nil {
		t.Fatal(err)
	}
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()
	if _, err := db.Exec(`insert into resources(id,data) values(1,'{"ip":"192.0.2.20"}')`); err != nil {
		t.Fatal(err)
	}
	duplicate, err := genericDuplicate("resources", genericItem{Data: `{"ip":"192.0.2.20"}`}, 0)
	if err != nil || !duplicate {
		t.Fatalf("resource duplicate=%v err=%v", duplicate, err)
	}
	duplicate, err = genericDuplicate("resources", genericItem{Data: `{"ip":"192.0.2.20"}`}, 1)
	if err != nil || duplicate {
		t.Fatalf("self update duplicate=%v err=%v", duplicate, err)
	}
	if _, err := db.Exec(`insert into services(id,data) values(1,'{"ip":"192.0.2.20","port":443,"protocol":"tcp"}')`); err != nil {
		t.Fatal(err)
	}
	duplicate, err = genericDuplicate("services", genericItem{Data: `{"ip":"192.0.2.20","port":443,"protocol":"tcp"}`}, 0)
	if err != nil || !duplicate {
		t.Fatalf("service duplicate=%v err=%v", duplicate, err)
	}
}
