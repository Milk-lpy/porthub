package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"porthub/internal/snapshots"
	"strings"
	"sync"
	"time"
)

type backendStatus struct {
	Target      string    `json:"target"`
	Healthy     bool      `json:"healthy"`
	StatusCode  int       `json:"status_code,omitempty"`
	LastChecked time.Time `json:"last_checked"`
	Error       string    `json:"error,omitempty"`
	Failures    int       `json:"consecutive_failures,omitempty"`
}

var proxyHTTPSPort = "18443"
var backendMu sync.RWMutex
var backendStatuses = map[string]backendStatus{}
var selectionMu sync.Mutex
var selectionCounters = map[string]uint64{}

func serveHTTPProxy(addr string) {
	if addr == "" {
		return
	}
	srv := proxyServer(addr)
	log.Println("porthub-edge-http-proxy", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Println("http proxy stopped:", err)
	}
}

func serveHTTPSProxy(addr, certFile, keyFile string) {
	if addr == "" {
		return
	}
	store, err := newCertificateStore(certFile, keyFile)
	if err != nil {
		log.Println("https proxy certificate store failed:", err)
		return
	}
	managedCertificateMu.Lock()
	managedCertificates = store
	managedCertificateMu.Unlock()
	srv := proxyServer(addr)
	srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: store.getCertificate}
	log.Println("porthub-edge-https-proxy", addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Println("https proxy stopped:", err)
	}
}

func proxyServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", proxyRequest)
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
}

func proxyRequest(w http.ResponseWriter, r *http.Request) {
	if serveACMEChallenge(w, r) {
		return
	}
	proxy, ok := matchHTTPProxy(r)
	if !ok {
		http.Error(w, "porthub proxy route not found", http.StatusNotFound)
		return
	}
	if proxy.ForceTLS && r.TLS == nil {
		http.Redirect(w, r, httpsRedirectURL(r), http.StatusPermanentRedirect)
		return
	}
	targetValue, ok := selectProxyTarget(proxy)
	if !ok {
		http.Error(w, "all upstreams are unavailable", http.StatusServiceUnavailable)
		return
	}
	target, err := url.Parse(targetValue)
	if err != nil {
		http.Error(w, "bad proxy target", http.StatusBadGateway)
		return
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)
		if proxy.PreserveHost {
			req.Host = r.Host
		} else {
			req.Host = target.Host
		}
		req.Header.Set("X-Forwarded-Host", r.Host)
		req.Header.Set("X-Forwarded-Proto", forwardedProto(r))
		for name, value := range proxy.Headers {
			req.Header.Set(name, value)
		}
	}
	rp.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
	}
	rp.ErrorHandler = func(w http.ResponseWriter, request *http.Request, proxyErr error) {
		log.Printf("proxy upstream error route=%q target=%q method=%s: %v", proxy.Name, targetValue, request.Method, proxyErr)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}
	start := time.Now()
	rp.ServeHTTP(w, r)
	log.Printf("proxy access route=%q method=%s host=%q path=%q duration_ms=%d", proxy.Name, r.Method, r.Host, r.URL.Path, time.Since(start).Milliseconds())
}

func forwardedProto(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func matchHTTPProxy(r *http.Request) (snapshots.HTTPProxy, bool) {
	host := strings.ToLower(stripPort(r.Host))
	path := r.URL.Path
	mu.Lock()
	defer mu.Unlock()
	var best snapshots.HTTPProxy
	bestLen := -1
	for _, p := range current.HTTPProxies {
		if !p.Enabled || strings.ToLower(p.Host) != host {
			continue
		}
		prefix := p.Path
		if prefix == "" {
			prefix = "/"
		}
		if strings.HasPrefix(path, prefix) && len(prefix) > bestLen {
			best = p
			bestLen = len(prefix)
		}
	}
	return best, bestLen >= 0
}

func proxyTargets(proxy snapshots.HTTPProxy) []string {
	if len(proxy.Targets) > 0 {
		return proxy.Targets
	}
	if proxy.Target != "" {
		return []string{proxy.Target}
	}
	return nil
}

func selectProxyTarget(proxy snapshots.HTTPProxy) (string, bool) {
	targets := proxyTargets(proxy)
	if len(targets) == 0 {
		return "", false
	}
	available := targets
	if proxy.HealthPath != "" {
		available = nil
		backendMu.RLock()
		for _, target := range targets {
			status, exists := backendStatuses[backendKey(target, proxy.HealthPath)]
			if !exists || status.Healthy || status.Failures < 2 {
				available = append(available, target)
			}
		}
		backendMu.RUnlock()
		if len(available) == 0 {
			return "", false
		}
	}
	key := strings.ToLower(proxy.Host) + "|" + proxy.Path
	selectionMu.Lock()
	index := selectionCounters[key] % uint64(len(available))
	selectionCounters[key]++
	selectionMu.Unlock()
	return available[index], true
}

func startProxyHealthChecks(interval time.Duration) {
	if interval <= 0 {
		interval = 20 * time.Second
	}
	checkProxyBackends()
	time.Sleep(2 * time.Second)
	checkProxyBackends()
	for range time.NewTicker(interval).C {
		checkProxyBackends()
	}
}

func checkProxyBackends() {
	mu.Lock()
	proxies := append([]snapshots.HTTPProxy(nil), current.HTTPProxies...)
	mu.Unlock()
	client := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	for _, proxy := range proxies {
		if !proxy.Enabled || proxy.HealthPath == "" {
			continue
		}
		for _, target := range proxyTargets(proxy) {
			status := checkProxyBackend(client, target, proxy.HealthPath)
			backendMu.Lock()
			previous := backendStatuses[backendKey(target, proxy.HealthPath)]
			if status.Healthy {
				status.Failures = 0
			} else {
				status.Failures = previous.Failures + 1
			}
			backendStatuses[backendKey(target, proxy.HealthPath)] = status
			backendMu.Unlock()
		}
	}
}

func checkProxyBackend(client *http.Client, target, healthPath string) backendStatus {
	status := backendStatus{Target: target, LastChecked: time.Now().UTC()}
	base, err := url.Parse(target)
	if err != nil {
		status.Error = "invalid target"
		return status
	}
	base.Path = healthPath
	base.RawQuery = ""
	request, _ := http.NewRequest(http.MethodGet, base.String(), nil)
	response, err := client.Do(request)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	response.Body.Close()
	status.StatusCode = response.StatusCode
	status.Healthy = response.StatusCode >= 200 && response.StatusCode < 500
	return status
}

func proxyHealth(w http.ResponseWriter, r *http.Request) {
	backendMu.RLock()
	items := make([]backendStatus, 0, len(backendStatuses))
	for _, status := range backendStatuses {
		items = append(items, status)
	}
	backendMu.RUnlock()
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(items)
}

func httpsRedirectURL(r *http.Request) string {
	host := stripPort(r.Host)
	if proxyHTTPSPort != "" && proxyHTTPSPort != "443" {
		host = net.JoinHostPort(host, proxyHTTPSPort)
	}
	return fmt.Sprintf("https://%s%s", host, r.URL.RequestURI())
}

func backendKey(target, healthPath string) string { return target + "|" + healthPath }

func stripPort(host string) string {
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		return parsed
	}
	return strings.Trim(host, "[]")
}
