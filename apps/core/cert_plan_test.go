package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildCertificatePlanManualRenewal(t *testing.T) {
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	dataDir = t.TempDir()
	cert := certificateItem{
		ID:        1,
		Name:      "NAS",
		Domains:   []string{"nas.example.com"},
		Mode:      "manual",
		Status:    "issued",
		ExpiresAt: now.Add(10 * 24 * time.Hour).Format(time.RFC3339),
		KeyRef:    filepath.Join(dataDir, "certs", "nas.key"),
		Enabled:   true,
	}
	result := buildCertificatePlan(cert, now)
	if !result.OK {
		t.Fatalf("unexpected blockers: %+v", result.Blockers)
	}
	if !result.RenewalRequired {
		t.Fatal("expected renewal window")
	}
}

func TestBuildCertificatePlanHTTP01WildcardBlocked(t *testing.T) {
	result := buildCertificatePlan(certificateItem{
		ID:      2,
		Name:    "Wildcard",
		Domains: []string{"*.example.com"},
		Mode:    "acme_http_01",
		Status:  "draft",
		Enabled: true,
	}, time.Now())
	if result.OK {
		t.Fatal("expected wildcard HTTP-01 blocker")
	}
	if !containsBlocker(result.Blockers, "wildcard") {
		t.Fatalf("missing wildcard blocker: %+v", result.Blockers)
	}
}

func TestValidateCertificateKeyRefRestriction(t *testing.T) {
	dataDir = t.TempDir()
	if err := validateCertificateKeyRef(filepath.Join(dataDir, "certs", "site.key")); err != nil {
		t.Fatal(err)
	}
	if err := validateCertificateKeyRef("/tmp/site.key"); err == nil {
		t.Fatal("expected key_ref path restriction")
	}
}

func containsBlocker(items []string, needle string) bool {
	for _, item := range items {
		if strings.Contains(item, needle) {
			return true
		}
	}
	return false
}
