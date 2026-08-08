package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"porthub/internal/snapshots"
	"strings"
	"sync"
	"time"
)

var acmeChallenges = struct {
	sync.RWMutex
	set snapshots.ACMEChallengeSet
}{}

func loadACMEChallenges() {
	body, err := os.ReadFile(filepath.Join(data, "acme-challenges.json"))
	if err != nil {
		return
	}
	var set snapshots.ACMEChallengeSet
	if json.Unmarshal(body, &set) == nil && set.ExpiresAt.After(time.Now()) {
		acmeChallenges.Lock()
		acmeChallenges.set = set
		acmeChallenges.Unlock()
	}
}

func applyACMEChallenges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var set snapshots.ACMEChallengeSet
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&set) != nil {
		http.Error(w, "invalid ACME challenge set", http.StatusBadRequest)
		return
	}
	if err := snapshots.VerifyACMEChallengeSet(set, pub, time.Now(), seen); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	acmeChallenges.Lock()
	if set.Version <= acmeChallenges.set.Version {
		acmeChallenges.Unlock()
		http.Error(w, "stale ACME challenge set", http.StatusConflict)
		return
	}
	acmeChallenges.set = set
	acmeChallenges.Unlock()
	body, _ := json.Marshal(set)
	if err := os.WriteFile(filepath.Join(data, "acme-challenges.json"), body, 0600); err != nil {
		http.Error(w, "failed to persist ACME challenge set", http.StatusInternalServerError)
		return
	}
	writeACMEJSON(w, map[string]any{"ok": true, "entries": len(set.Entries), "expires_at": set.ExpiresAt})
}

func serveACMEChallenge(w http.ResponseWriter, r *http.Request) bool {
	const prefix = "/.well-known/acme-challenge/"
	if r.Method != http.MethodGet && r.Method != http.MethodHead || !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	token := strings.TrimPrefix(r.URL.Path, prefix)
	host := strings.ToLower(stripPort(r.Host))
	acmeChallenges.RLock()
	set := acmeChallenges.set
	acmeChallenges.RUnlock()
	if !set.ExpiresAt.After(time.Now()) {
		return false
	}
	for _, entry := range set.Entries {
		if strings.EqualFold(entry.Domain, host) && entry.Token == token {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte(entry.KeyAuthorization))
			}
			return true
		}
	}
	return false
}

func writeACMEJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
