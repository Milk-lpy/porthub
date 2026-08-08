package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"porthub/internal/snapshots"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxImportedCIDRs = 5000

type ipSetImportRequest struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Action  string `json:"action"`
	Source  string `json:"source"`
	Enabled bool   `json:"enabled"`
}

func ipSets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var set snapshots.IPSet
		if err := json.NewDecoder(r.Body).Decode(&set); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		normalizeIPSet(&set)
		if err := snapshots.ValidateIPSets([]snapshots.IPSet{set}); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := insertIPSet(set); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit(actor(r), "ip_set_create", set.Name)
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		var set snapshots.IPSet
		if err := json.NewDecoder(r.Body).Decode(&set); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		id, err := strconv.Atoi(set.ID)
		if err != nil || id < 1 {
			http.Error(w, "valid id required", http.StatusBadRequest)
			return
		}
		normalizeIPSet(&set)
		if err := snapshots.ValidateIPSets([]snapshots.IPSet{set}); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cidrs, _ := json.Marshal(set.CIDRs)
		db.Exec("update ip_sets set name=?,kind=?,action=?,cidrs=?,enabled=?,updated_at=? where id=?", set.Name, set.Kind, string(set.Action), string(cidrs), boolInt(set.Enabled), time.Now().Format(time.RFC3339), id)
		audit(actor(r), "ip_set_update", set.ID)
		writeJSON(w, map[string]any{"ok": true})
	case http.MethodDelete:
		deleteByID(w, r, "ip_sets", "ip_set_delete")
	default:
		writeJSON(w, loadIPSets(0))
	}
}

func ipSetImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ipSetImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	set, err := buildImportedIPSet(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := insertIPSet(set); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(actor(r), "ip_set_import", set.Name+" "+strconv.Itoa(len(set.CIDRs)))
	writeJSON(w, map[string]any{"ok": true, "name": set.Name, "kind": set.Kind, "count": len(set.CIDRs)})
}

func loadIPSets(excludeID int) []snapshots.IPSet {
	rows, _ := db.Query("select id,name,kind,action,cidrs,enabled from ip_sets order by id")
	defer rows.Close()
	var out []snapshots.IPSet
	for rows.Next() {
		var id, enabled int
		var set snapshots.IPSet
		var cidrsText string
		rows.Scan(&id, &set.Name, &set.Kind, &set.Action, &cidrsText, &enabled)
		if id == excludeID {
			continue
		}
		json.Unmarshal([]byte(cidrsText), &set.CIDRs)
		set.ID = strconv.Itoa(id)
		set.Enabled = enabled == 1
		out = append(out, set)
	}
	return out
}

func normalizeIPSet(set *snapshots.IPSet) {
	if set.Kind == "" {
		set.Kind = "custom"
	}
	if set.Action == "" {
		set.Action = snapshots.ACLDeny
	}
}

func buildImportedIPSet(req ipSetImportRequest) (snapshots.IPSet, error) {
	set := snapshots.IPSet{
		Name:    strings.TrimSpace(req.Name),
		Kind:    strings.TrimSpace(req.Kind),
		Action:  snapshots.ACLAction(strings.TrimSpace(req.Action)),
		Enabled: req.Enabled,
	}
	normalizeIPSet(&set)
	if set.Kind != "geoip" && set.Kind != "asn" && set.Kind != "custom" {
		return set, errors.New("kind must be custom, geoip or asn")
	}
	cidrs, err := parseCIDRImport(req.Source)
	if err != nil {
		return set, err
	}
	if len(cidrs) > maxImportedCIDRs {
		return set, errors.New("too many CIDRs in one import")
	}
	set.CIDRs = cidrs
	if err := snapshots.ValidateIPSets([]snapshots.IPSet{set}); err != nil {
		return set, err
	}
	return set, nil
}

func parseCIDRImport(source string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(source, "\n") {
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.NewReplacer(",", " ", "\t", " ", "\r", " ").Replace(line)
		for _, token := range strings.Fields(line) {
			cidr, err := normalizeCIDRToken(token)
			if err != nil {
				return nil, err
			}
			if seen[cidr] {
				continue
			}
			seen[cidr] = true
			out = append(out, cidr)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, errors.New("empty CIDR import")
	}
	return out, nil
}

func normalizeCIDRToken(token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("empty CIDR token")
	}
	if _, network, err := net.ParseCIDR(token); err == nil {
		return network.String(), nil
	}
	ip := net.ParseIP(token)
	if ip == nil {
		return "", errors.New("invalid CIDR token: " + token)
	}
	if ip.To4() != nil {
		return ip.String() + "/32", nil
	}
	return ip.String() + "/128", nil
}

func insertIPSet(set snapshots.IPSet) error {
	cidrs, _ := json.Marshal(set.CIDRs)
	now := time.Now().Format(time.RFC3339)
	_, err := db.Exec("insert into ip_sets(name,kind,action,cidrs,enabled,created_at,updated_at) values(?,?,?,?,?,?,?)", set.Name, set.Kind, string(set.Action), string(cidrs), boolInt(set.Enabled), now, now)
	return err
}
