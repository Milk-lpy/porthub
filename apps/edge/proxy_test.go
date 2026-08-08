package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"porthub/internal/snapshots"
	"strings"
	"testing"
)

func TestMatchHTTPProxyLongestPath(t *testing.T) {
	current = snapshots.Snapshot{HTTPProxies: []snapshots.HTTPProxy{
		{Host: "app.example", Path: "/", Target: "http://10.0.0.1:80", Enabled: true},
		{Host: "app.example", Path: "/api", Target: "http://10.0.0.2:80", Enabled: true},
	}}
	r, _ := http.NewRequest(http.MethodGet, "http://app.example/api/status", nil)
	r.Host = "app.example"
	p, ok := matchHTTPProxy(r)
	if !ok || p.Target != "http://10.0.0.2:80" {
		t.Fatalf("bad match: %#v ok=%v", p, ok)
	}
}

func TestProxyRoundRobinAndHeaders(t *testing.T) {
	makeBackend := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"backend": name, "header": r.Header.Get("X-PortHub-Test"), "host": r.Host})
		}))
	}
	first := makeBackend("first")
	defer first.Close()
	second := makeBackend("second")
	defer second.Close()
	current = snapshots.Snapshot{HTTPProxies: []snapshots.HTTPProxy{{
		Name: "app", Host: "app.example", Path: "/", Target: first.URL, Targets: []string{first.URL, second.URL},
		Headers: map[string]string{"X-PortHub-Test": "ok"}, PreserveHost: true, Enabled: true,
	}}}
	selectionCounters = map[string]uint64{}
	for index, expected := range []string{"first", "second"} {
		request := httptest.NewRequest(http.MethodGet, "http://app.example/test", nil)
		request.Host = "app.example"
		recorder := httptest.NewRecorder()
		proxyRequest(recorder, request)
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"backend":"`+expected+`"`) {
			t.Fatalf("request %d status=%d body=%s", index, recorder.Code, recorder.Body.String())
		}
		if !strings.Contains(recorder.Body.String(), `"header":"ok"`) || !strings.Contains(recorder.Body.String(), `"host":"app.example"`) {
			t.Fatalf("headers were not forwarded: %s", recorder.Body.String())
		}
	}
}

func TestForceTLSRedirect(t *testing.T) {
	oldPort := proxyHTTPSPort
	proxyHTTPSPort = "18443"
	defer func() { proxyHTTPSPort = oldPort }()
	current = snapshots.Snapshot{HTTPProxies: []snapshots.HTTPProxy{{Host: "app.example", Path: "/", Target: "http://127.0.0.1", Enabled: true, ForceTLS: true}}}
	request := httptest.NewRequest(http.MethodGet, "http://app.example/status?full=1", nil)
	request.Host = "app.example"
	recorder := httptest.NewRecorder()
	proxyRequest(recorder, request)
	if recorder.Code != http.StatusPermanentRedirect || recorder.Header().Get("Location") != "https://app.example:18443/status?full=1" {
		t.Fatalf("status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestHealthSelectionSkipsFailedBackend(t *testing.T) {
	proxy := snapshots.HTTPProxy{Host: "app.example", Path: "/", Targets: []string{"http://one", "http://two"}, HealthPath: "/health", Enabled: true}
	backendStatuses = map[string]backendStatus{
		backendKey("http://one", "/health"): {Target: "http://one", Healthy: false, Failures: 2},
		backendKey("http://two", "/health"): {Target: "http://two", Healthy: true},
	}
	got, ok := selectProxyTarget(proxy)
	if !ok || got != "http://two" {
		t.Fatalf("target=%q ok=%v", got, ok)
	}
}

func TestWildcardMatchesOneLabel(t *testing.T) {
	if !wildcardMatches("*.example.test", "app.example.test") {
		t.Fatal("single-label wildcard did not match")
	}
	if wildcardMatches("*.example.test", "deep.app.example.test") {
		t.Fatal("wildcard matched multiple labels")
	}
}
