package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// AirSIM runs as a separate service. PortHub only checks its HTTP readiness;
// it never stores the APNs private key, calls, SMS, or media payloads.
const defaultAirSIMHealthURL = "http://127.0.0.1:8787/healthz"

type airsimIntegrationState struct {
	Configured bool      `json:"configured"`
	Reachable  bool      `json:"reachable"`
	Status     string    `json:"status"`
	CheckedAt  time.Time `json:"checked_at"`
	Source     string    `json:"source"`
}

// Only an administrator-managed environment variable can select this endpoint.
// Constrain the destination to a literal private/loopback address to prevent a
// public HTTP target (or redirect) from turning the status check into an SSRF.
func validateAirSIMHealthURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") ||
		u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/healthz" {
		return nil, errors.New("invalid AirSIM health URL")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || (!ip.IsLoopback() && !ip.IsPrivate())) {
		return nil, errors.New("AirSIM health target must be a private IP or localhost")
	}
	return u, nil
}

func checkAirSIMHealth(ctx context.Context, raw string) bool {
	u, err := validateAirSIMHealthURL(raw)
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
			TLSHandshakeTimeout: 2 * time.Second,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func airsimIntegrationStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw := strings.TrimSpace(os.Getenv("AIRSIM_RELAY_HEALTH_URL"))
	source := "default_loopback"
	configured := raw != ""
	if !configured {
		raw = defaultAirSIMHealthURL
	} else {
		source = "environment"
	}
	state := airsimIntegrationState{
		Configured: configured, CheckedAt: time.Now().UTC(), Source: source,
		Status: "unreachable",
	}
	if _, err := validateAirSIMHealthURL(raw); err != nil {
		state.Status = "invalid_configuration"
	} else if checkAirSIMHealth(r.Context(), raw) {
		state.Reachable = true
		state.Status = "http_ready"
	}
	// HTTP readiness deliberately does not claim that APNs, device heartbeats,
	// SMS delivery, PushKit wake-up or bidirectional PCM have passed testing.
	writeJSON(w, state)
}
