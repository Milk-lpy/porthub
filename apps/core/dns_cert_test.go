package main

import (
	"encoding/json"
	"testing"
)

func TestDomainValidationAndDefaults(t *testing.T) {
	item := domainItem{Name: "Home", Zone: "Example.COM.", Enabled: true}
	normalizeDomainItem(&item)
	if item.Zone != "example.com" || item.Provider != "external" || item.ManagedBy != "porthub" {
		t.Fatalf("unexpected defaults: %+v", item)
	}
	if err := validateDomainItem(item); err != nil {
		t.Fatal(err)
	}
	item.Zone = "-bad.example"
	if err := validateDomainItem(item); err == nil {
		t.Fatal("expected invalid domain")
	}
}

func TestDDNSProviderSecretRedaction(t *testing.T) {
	raw := json.RawMessage(`{"endpoint":"https://hook.example/ddns","token":"secret","api_key":"key","note":"keep"}`)
	redacted := redactProviderConfig(raw)
	if string(redacted) == string(raw) {
		t.Fatal("secret fields were not redacted")
	}
	var cfg map[string]string
	if err := json.Unmarshal(redacted, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["token"] != "********" || cfg["api_key"] != "********" || cfg["note"] != "keep" {
		t.Fatalf("bad redaction: %#v", cfg)
	}
}

func TestDDNSRecordValidation(t *testing.T) {
	item := ddnsRecordItem{Name: "Edge", FQDN: "Edge.Example.COM."}
	normalizeDDNSRecord(&item)
	if item.FQDN != "edge.example.com" || item.RecordType != "A" || item.IPSource != "edge_public" || item.TTL != 600 {
		t.Fatalf("unexpected defaults: %+v", item)
	}
	if err := validateDDNSRecord(item); err == nil {
		t.Fatal("expected provider_id requirement")
	}
	item.ProviderID = 1
	if err := validateDDNSRecord(item); err != nil {
		t.Fatal(err)
	}
	item.TTL = 30
	if err := validateDDNSRecord(item); err == nil {
		t.Fatal("expected ttl validation failure")
	}
}

func TestCertificateValidation(t *testing.T) {
	item := certificateItem{Name: "NAS", Domains: []string{"NAS.Example.COM."}}
	normalizeCertificateItem(&item)
	if item.Domains[0] != "nas.example.com" || item.Mode != "manual" || item.Status != "draft" {
		t.Fatalf("unexpected defaults: %+v", item)
	}
	if err := validateCertificateItem(item); err != nil {
		t.Fatal(err)
	}
	item.Domains = []string{"*.example.com"}
	if err := validateCertificateItem(item); err != nil {
		t.Fatal(err)
	}
	item.Domains = []string{"bad..example.com"}
	if err := validateCertificateItem(item); err == nil {
		t.Fatal("expected invalid certificate domain")
	}
}
