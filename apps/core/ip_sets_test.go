package main

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestParseCIDRImport(t *testing.T) {
	got, err := parseCIDRImport(`
		# China sample
		203.0.113.9
		198.51.100.0/24, 2001:db8::/32
		203.0.113.9 # duplicate
	`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.0/24", "2001:db8::/32", "203.0.113.9/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected CIDRs got=%v want=%v", got, want)
	}
}

func TestParseCIDRImportRejectsInvalid(t *testing.T) {
	if _, err := parseCIDRImport("203.0.113.0/24\nnot-a-cidr"); err == nil {
		t.Fatal("expected invalid CIDR error")
	}
}

func TestBuildImportedIPSet(t *testing.T) {
	set, err := buildImportedIPSet(ipSetImportRequest{
		Name:    "CN Geo",
		Kind:    "geoip",
		Action:  "deny",
		Enabled: true,
		Source:  "203.0.113.0/24\n2001:db8::/32",
	})
	if err != nil {
		t.Fatal(err)
	}
	if set.Kind != "geoip" || len(set.CIDRs) != 2 || !set.Enabled {
		t.Fatalf("unexpected imported set: %+v", set)
	}
	if _, err := buildImportedIPSet(ipSetImportRequest{Name: "bad", Kind: "planet", Action: "deny", Source: "203.0.113.0/24"}); err == nil {
		t.Fatal("expected invalid kind")
	}
	var b strings.Builder
	for i := 0; i < maxImportedCIDRs+1; i++ {
		b.WriteString("10.")
		b.WriteString(strconv.Itoa((i / 65536) % 256))
		b.WriteString(".")
		b.WriteString(strconv.Itoa((i / 256) % 256))
		b.WriteString(".")
		b.WriteString(strconv.Itoa(i % 256))
		b.WriteString("\n")
	}
	tooMany := b.String()
	if _, err := buildImportedIPSet(ipSetImportRequest{Name: "many", Kind: "asn", Action: "deny", Source: tooMany}); err == nil {
		t.Fatal("expected too many CIDRs")
	}
}
