package main

import (
	"encoding/json"
	"net/http"
	"porthub/internal/snapshots"
	"strconv"
	"strings"
	"time"
)

func httpProxies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var p snapshots.HTTPProxy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		normalizeHTTPProxy(&p)
		if err := snapshots.ValidateHTTPProxies([]snapshots.HTTPProxy{p}); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		all := append(loadHTTPProxies(0), p)
		if err := snapshots.ValidateHTTPProxies(all); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now().Format(time.RFC3339)
		targets, _ := json.Marshal(p.Targets)
		headers, _ := json.Marshal(p.Headers)
		_, err := db.Exec(`insert into http_proxies(name,host,path,target,targets,headers,health_path,load_balance,enabled,force_tls,websocket,preserve_host,created_at,updated_at)
			values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, p.Name, p.Host, p.Path, p.Target, string(targets), string(headers), p.HealthPath, p.LoadBalance,
			boolInt(p.Enabled), boolInt(p.ForceTLS), boolInt(p.WebSocket), boolInt(p.PreserveHost), now, now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit(actor(r), "http_proxy_create", p.Name)
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		var p snapshots.HTTPProxy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		normalizeHTTPProxy(&p)
		id, err := strconv.Atoi(p.ID)
		if err != nil || id < 1 {
			http.Error(w, "valid id required", http.StatusBadRequest)
			return
		}
		all := append(loadHTTPProxies(id), p)
		if err := snapshots.ValidateHTTPProxies(all); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		targets, _ := json.Marshal(p.Targets)
		headers, _ := json.Marshal(p.Headers)
		if _, err := db.Exec(`update http_proxies set name=?,host=?,path=?,target=?,targets=?,headers=?,health_path=?,load_balance=?,enabled=?,force_tls=?,websocket=?,preserve_host=?,updated_at=? where id=?`,
			p.Name, p.Host, p.Path, p.Target, string(targets), string(headers), p.HealthPath, p.LoadBalance, boolInt(p.Enabled), boolInt(p.ForceTLS),
			boolInt(p.WebSocket), boolInt(p.PreserveHost), time.Now().Format(time.RFC3339), id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit(actor(r), "http_proxy_update", p.ID)
		writeJSON(w, map[string]any{"ok": true})
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		db.Exec("delete from http_proxies where id=?", id)
		audit(actor(r), "http_proxy_delete", id)
		writeJSON(w, map[string]any{"ok": true})
	default:
		writeJSON(w, loadHTTPProxies(0))
	}
}

func loadHTTPProxies(excludeID int) []snapshots.HTTPProxy {
	rows, _ := db.Query(`select id,name,host,path,target,coalesce(targets,''),coalesce(headers,''),coalesce(health_path,''),
		coalesce(load_balance,'round_robin'),enabled,force_tls,coalesce(websocket,1),coalesce(preserve_host,0) from http_proxies order by id`)
	defer rows.Close()
	var out []snapshots.HTTPProxy
	for rows.Next() {
		var id, enabled, forceTLS, websocket, preserveHost int
		var targets, headers string
		var p snapshots.HTTPProxy
		rows.Scan(&id, &p.Name, &p.Host, &p.Path, &p.Target, &targets, &headers, &p.HealthPath, &p.LoadBalance, &enabled, &forceTLS, &websocket, &preserveHost)
		if id == excludeID {
			continue
		}
		p.ID = strconv.Itoa(id)
		p.Enabled = enabled == 1
		p.ForceTLS = forceTLS == 1
		p.WebSocket = websocket == 1
		p.PreserveHost = preserveHost == 1
		_ = json.Unmarshal([]byte(targets), &p.Targets)
		_ = json.Unmarshal([]byte(headers), &p.Headers)
		normalizeHTTPProxy(&p)
		out = append(out, p)
	}
	return out
}

func normalizeHTTPProxy(p *snapshots.HTTPProxy) {
	p.Host = strings.ToLower(strings.TrimSpace(p.Host))
	p.Path = strings.TrimSpace(p.Path)
	if p.Path == "" {
		p.Path = "/"
	}
	p.Target = strings.TrimSpace(p.Target)
	clean := make([]string, 0, len(p.Targets)+1)
	seen := map[string]bool{}
	for _, target := range append([]string{p.Target}, p.Targets...) {
		target = strings.TrimSpace(target)
		if target != "" && !seen[target] {
			clean = append(clean, target)
			seen[target] = true
		}
	}
	p.Targets = clean
	if len(clean) > 0 {
		p.Target = clean[0]
	}
	if p.LoadBalance == "" {
		p.LoadBalance = "round_robin"
	}
}
