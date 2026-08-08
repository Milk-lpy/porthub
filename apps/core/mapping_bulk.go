package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"porthub/internal/snapshots"
	"strconv"
	"time"
)

type mappingBulkRequest struct {
	Action string   `json:"action"`
	IDs    []string `json:"ids"`
}

type mappingImportRequest struct {
	Mode     string              `json:"mode"`
	Mappings []snapshots.Mapping `json:"mappings"`
}

func mappingExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{
		"exported_at": time.Now().UTC().Format(time.RFC3339),
		"mappings":    loadMappings(0),
	})
}

func mappingImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req mappingImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Mode == "" {
		req.Mode = "append"
	}
	if req.Mode != "append" {
		http.Error(w, "only append import is supported", http.StatusBadRequest)
		return
	}
	if len(req.Mappings) == 0 || len(req.Mappings) > 200 {
		http.Error(w, "import requires 1-200 mappings", http.StatusBadRequest)
		return
	}
	for i := range req.Mappings {
		req.Mappings[i].ID = ""
		normalizeMapping(&req.Mappings[i])
	}
	all := append(loadMappings(0), req.Mappings...)
	if err := snapshots.ValidateMappings(all); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	for _, m := range req.Mappings {
		if _, err = insertMapping(tx, m, actor(r), false); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audit(actor(r), "mapping_import", strconv.Itoa(len(req.Mappings)))
	writeJSON(w, map[string]any{"ok": true, "created": len(req.Mappings)})
}

func mappingBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req mappingBulkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ids, err := parseMappingIDs(req.IDs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	current := loadMappings(0)
	switch req.Action {
	case "enable", "disable":
		next, err := setMappingEnabled(current, ids, req.Action == "enable")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := snapshots.ValidateMappings(next); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case "delete":
	default:
		http.Error(w, "action must be enable, disable or delete", http.StatusBadRequest)
		return
	}
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	for id := range ids {
		switch req.Action {
		case "enable":
			_, err = tx.Exec("update mappings set enabled=1 where id=?", id)
		case "disable":
			_, err = tx.Exec("update mappings set enabled=0 where id=?", id)
		case "delete":
			_, err = tx.Exec("delete from mappings where id=?", id)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audit(actor(r), "mapping_bulk_"+req.Action, strconv.Itoa(len(ids)))
	writeJSON(w, map[string]any{"ok": true, "affected": len(ids)})
}

func parseMappingIDs(raw []string) (map[int]bool, error) {
	if len(raw) == 0 || len(raw) > 500 {
		return nil, errors.New("ids must contain 1-500 items")
	}
	ids := map[int]bool{}
	for _, value := range raw {
		id, err := strconv.Atoi(value)
		if err != nil || id < 1 {
			return nil, errors.New("invalid mapping id")
		}
		ids[id] = true
	}
	return ids, nil
}

func setMappingEnabled(ms []snapshots.Mapping, ids map[int]bool, enabled bool) ([]snapshots.Mapping, error) {
	seen := map[int]bool{}
	for i := range ms {
		id, _ := strconv.Atoi(ms[i].ID)
		if ids[id] {
			ms[i].Enabled = enabled
			seen[id] = true
		}
	}
	if len(seen) != len(ids) {
		return nil, errors.New("mapping id not found")
	}
	return ms, nil
}
