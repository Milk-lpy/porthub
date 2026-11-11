package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateAirSIMHealthURL(t *testing.T) {
	for _, value := range []string{
		"http://127.0.0.1:8787/healthz",
		"http://10.66.0.2:18787/healthz",
		"http://192.168.1.12:18787/healthz",
		"http://localhost:8787/healthz",
	} {
		if _, err := validateAirSIMHealthURL(value); err != nil {
			t.Errorf("expected allowed endpoint %q: %v", value, err)
		}
	}
	for _, value := range []string{
		"https://example.com/healthz", "http://8.8.8.8/healthz",
		"http://127.0.0.1:8787/admin", "file:///etc/passwd",
		"http://user:password@127.0.0.1/healthz",
		"http://127.0.0.1/healthz?token=secret",
	} {
		if _, err := validateAirSIMHealthURL(value); err == nil {
			t.Errorf("expected rejected endpoint %q", value)
		}
	}
}

func TestAirSIMHealthDoesNotFollowRedirects(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/", http.StatusFound)
	}))
	defer s.Close()
	if checkAirSIMHealth(context.Background(), s.URL+"/healthz") {
		t.Fatal("redirect response must not be considered healthy")
	}
}

func TestAirSIMIntegrationStatus(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Fatal("unexpected health path")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()
	t.Setenv("AIRSIM_RELAY_HEALTH_URL", s.URL+"/healthz")
	rec := httptest.NewRecorder()
	airsimIntegrationStatus(rec, httptest.NewRequest(http.MethodGet, "/api/integrations/airsim", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "\"http_ready\"") {
		t.Fatalf("unexpected response: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	airsimIntegrationStatus(rec, httptest.NewRequest(http.MethodPost, "/api/integrations/airsim", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST must not be permitted: %d", rec.Code)
	}
}

func TestAirSIMStatusRequiresSession(t *testing.T) {
	// Existing Core route is wrapped in requireAuth; readonly users can view
	// health, and there is intentionally no endpoint to run shell commands.
	if !roleAllowed("readonly", http.MethodGet, "/api/integrations/airsim") {
		t.Fatal("readonly users should be able to inspect AirSIM readiness")
	}
	if roleAllowed("readonly", http.MethodPost, "/api/integrations/airsim") {
		t.Fatal("readonly users must not mutate integrations")
	}
}
