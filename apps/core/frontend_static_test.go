package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFrontendHandlerRecoversWhenReleaseAppears(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "frontend")
	handler := frontendHandler(dir)

	before := httptest.NewRecorder()
	handler(before, httptest.NewRequest(http.MethodGet, "/", nil))
	if before.Code != http.StatusOK || !strings.Contains(before.Body.String(), "PortHub") {
		t.Fatalf("expected embedded recovery console, got %d", before.Code)
	}
	if before.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected recovery cache policy %q", before.Header().Get("Cache-Control"))
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><div id=app>vue release</div>"), 0644); err != nil {
		t.Fatal(err)
	}
	after := httptest.NewRecorder()
	handler(after, httptest.NewRequest(http.MethodGet, "/", nil))
	if after.Code != http.StatusOK || !strings.Contains(after.Body.String(), "vue release") {
		t.Fatalf("expected recovered Vue release, got %d %q", after.Code, after.Body.String())
	}
	if after.Header().Get("Cache-Control") != "no-cache, must-revalidate" {
		t.Fatalf("unexpected index cache policy %q", after.Header().Get("Cache-Control"))
	}
}

func TestFrontendHandlerCachesHashedAssets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("index"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "assets"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "app-abc123.js"), []byte("asset"), 0644); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	frontendHandler(dir)(response, httptest.NewRequest(http.MethodGet, "/assets/app-abc123.js", nil))
	if response.Code != http.StatusOK || response.Body.String() != "asset" {
		t.Fatalf("unexpected asset response %d %q", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("unexpected asset cache policy %q", response.Header().Get("Cache-Control"))
	}
}
