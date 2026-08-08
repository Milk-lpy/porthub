package main

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type roleLevel int

const (
	roleReadonly roleLevel = iota
	roleOperator
	roleAdmin
	roleSuperAdmin
)

func roleAllowed(role, method, path string) bool {
	return roleValue(role) >= requiredRole(method, path)
}

func roleValue(role string) roleLevel {
	switch role {
	case "super_admin":
		return roleSuperAdmin
	case "admin":
		return roleAdmin
	case "operator":
		return roleOperator
	default:
		return roleReadonly
	}
}

func requiredRole(method, path string) roleLevel {
	path = strings.TrimSuffix(path, "/")
	if path == "/api/ai/draft" {
		return roleReadonly
	}
	if strings.HasPrefix(path, "/api/users") {
		return roleSuperAdmin
	}
	if strings.HasPrefix(path, "/api/tokens") || strings.HasPrefix(path, "/api/backups") || strings.HasPrefix(path, "/api/webhooks") || strings.HasPrefix(path, "/api/updates") {
		return roleAdmin
	}
	if path == "/api/lan-scan" {
		return roleOperator
	}
	if !mutates(method) {
		return roleReadonly
	}
	if path == "/api/logout" || path == "/api/password/change" {
		return roleReadonly
	}
	operatorPrefixes := []string{
		"/api/mappings", "/api/deploy", "/api/http-proxies", "/api/resources",
		"/api/services", "/api/groups", "/api/templates/apply", "/api/traffic/snapshot",
		"/api/alerts", "/api/lan-scan",
	}
	for _, prefix := range operatorPrefixes {
		if strings.HasPrefix(path, prefix) {
			return roleOperator
		}
	}
	return roleAdmin
}

type loginAttempt struct {
	failures     []time.Time
	blockedUntil time.Time
}

const (
	loginFailureLimit = 5
	loginWindow       = 5 * time.Minute
	loginBlock        = 15 * time.Minute
	maxLimiterEntries = 10000
)

var loginLimits = struct {
	sync.Mutex
	entries map[string]loginAttempt
}{entries: map[string]loginAttempt{}}

var loginClock = time.Now

func loginLimitKey(r *http.Request, username string) string {
	host := r.RemoteAddr
	if parsed, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = parsed
	}
	return strings.ToLower(strings.TrimSpace(username)) + "\x00" + host
}

func loginRetryAfter(key string) (int, bool) {
	now := loginClock()
	loginLimits.Lock()
	defer loginLimits.Unlock()
	pruneLoginLimits(now)
	attempt := loginLimits.entries[key]
	if !attempt.blockedUntil.After(now) {
		return 0, false
	}
	seconds := int(attempt.blockedUntil.Sub(now).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return seconds, true
}

func recordLoginFailure(key string) {
	now := loginClock()
	loginLimits.Lock()
	defer loginLimits.Unlock()
	if _, exists := loginLimits.entries[key]; !exists {
		if len(loginLimits.entries) >= maxLimiterEntries {
			pruneLoginLimits(now)
			if len(loginLimits.entries) >= maxLimiterEntries {
				return // silently drop; a full map means we are under attack
			}
		}
	}
	attempt := loginLimits.entries[key]
	cutoff := now.Add(-loginWindow)
	kept := attempt.failures[:0]
	for _, failure := range attempt.failures {
		if failure.After(cutoff) {
			kept = append(kept, failure)
		}
	}
	attempt.failures = append(kept, now)
	if len(attempt.failures) >= loginFailureLimit {
		attempt.blockedUntil = now.Add(loginBlock)
	}
	loginLimits.entries[key] = attempt
}

func clearLoginFailures(key string) {
	loginLimits.Lock()
	delete(loginLimits.entries, key)
	loginLimits.Unlock()
}

func pruneLoginLimits(now time.Time) {
	for key, attempt := range loginLimits.entries {
		if !attempt.blockedUntil.After(now) && (len(attempt.failures) == 0 || attempt.failures[len(attempt.failures)-1].Before(now.Add(-loginWindow))) {
			delete(loginLimits.entries, key)
		}
	}
}

func writeRateLimited(w http.ResponseWriter, seconds int) {
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	http.Error(w, "login rate limit exceeded", http.StatusTooManyRequests)
}
