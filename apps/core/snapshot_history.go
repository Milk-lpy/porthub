package main

import (
	"encoding/json"
	"net/http"
	"porthub/internal/snapshots"
	"strconv"
	"time"
)

type snapshotHistoryItem struct {
	Version       int64  `json:"version"`
	CreatedAt     string `json:"created_at"`
	Operator      string `json:"operator"`
	SHA256        string `json:"sha256"`
	Status        string `json:"status"`
	Result        string `json:"result"`
	SourceVersion int64  `json:"source_version"`
}

func recordSnapshot(snapshot snapshots.Snapshot, status, result string, sourceVersion int64) error {
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	_, err = db.Exec(`insert into snapshot_history(version,created_at,operator,sha256,status,result,source_version,payload)
		values(?,?,?,?,?,?,?,?)`, snapshot.Version, snapshot.CreatedAt.Format(time.RFC3339Nano), snapshot.Operator, snapshot.SHA256, status, result, sourceVersion, string(payload))
	return err
}

func updateSnapshotResult(version int64, status, result string) {
	db.Exec("update snapshot_history set status=?,result=? where version=?", status, result, version)
}

func snapshotHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 50
	if value, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && value >= 1 && value <= 200 {
		limit = value
	}
	rows, err := db.Query(`select version,created_at,operator,sha256,status,result,source_version
		from snapshot_history order by version desc limit ?`, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	items := []snapshotHistoryItem{}
	for rows.Next() {
		var item snapshotHistoryItem
		if err := rows.Scan(&item.Version, &item.CreatedAt, &item.Operator, &item.SHA256, &item.Status, &item.Result, &item.SourceVersion); err == nil {
			items = append(items, item)
		}
	}
	writeJSON(w, items)
}

func snapshotRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		Version int64 `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Version < 1 {
		http.Error(w, "valid version required", http.StatusBadRequest)
		return
	}
	original, err := loadHistoricalSnapshot(request.Version)
	if err != nil {
		http.Error(w, "snapshot not found", http.StatusNotFound)
		return
	}
	original.Version = time.Now().UnixNano()
	original.CreatedAt = time.Now().UTC()
	original.Operator = actor(r)
	original.Nonce = ""
	original.SHA256 = ""
	original.Signature = ""
	rollback, err := snapshots.Sign(original, priv)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := recordSnapshot(rollback, "applying", "rollback requested", request.Version); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	coreRules, err := compileCoreForward(rollback)
	if err == nil {
		_, err = applyCoreForward(coreRules)
	}
	if err != nil {
		updateSnapshotResult(rollback.Version, "core_failed", err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	edgeResult, err := postSnapshotToEdge(rollback)
	if err != nil {
		updateSnapshotResult(rollback.Version, "edge_failed", err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if err := restoreSnapshotState(rollback); err != nil {
		updateSnapshotResult(rollback.Version, "database_failed", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	updateSnapshotResult(rollback.Version, "applied", "rollback of "+strconv.FormatInt(request.Version, 10))
	audit(actor(r), "snapshot_rollback", strconv.FormatInt(request.Version, 10))
	writeJSON(w, map[string]any{"ok": true, "version": rollback.Version, "source_version": request.Version, "edge": edgeResult})
}

func loadHistoricalSnapshot(version int64) (snapshots.Snapshot, error) {
	var payload string
	if err := db.QueryRow("select payload from snapshot_history where version=? and status='applied'", version).Scan(&payload); err != nil {
		return snapshots.Snapshot{}, err
	}
	var snapshot snapshots.Snapshot
	if err := json.Unmarshal([]byte(payload), &snapshot); err != nil {
		return snapshots.Snapshot{}, err
	}
	return snapshot, nil
}

func restoreSnapshotState(snapshot snapshots.Snapshot) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"mappings", "acl_rules", "ip_sets", "http_proxies"} {
		if _, err := tx.Exec("delete from " + table); err != nil {
			return err
		}
	}
	for _, mapping := range snapshot.Mappings {
		if _, err := insertMapping(tx, mapping, mapping.CreatedBy, true); err != nil {
			return err
		}
	}
	now := time.Now().Format(time.RFC3339)
	for _, rule := range snapshot.ACLRules {
		id, _ := strconv.Atoi(rule.ID)
		protocols, _ := json.Marshal(rule.Protocols)
		nodes, _ := json.Marshal(rule.NodeIDs)
		services, _ := json.Marshal(rule.ServiceIDs)
		groups, _ := json.Marshal(rule.GroupIDs)
		weekdays, _ := json.Marshal(rule.Weekdays)
		if _, err := tx.Exec(`insert into acl_rules(id,name,action,cidr,enabled,protocols,port_start,port_end,node_ids,service_ids,group_ids,weekdays,start_time,end_time,timezone,created_at,updated_at)
			values(nullif(?,0),?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, rule.Name, rule.Action, rule.CIDR, boolInt(rule.Enabled), string(protocols), rule.PortStart,
			rule.PortEnd, string(nodes), string(services), string(groups), string(weekdays), rule.StartTime, rule.EndTime, rule.Timezone, now, now); err != nil {
			return err
		}
	}
	for _, set := range snapshot.IPSets {
		cidrs, _ := json.Marshal(set.CIDRs)
		id, _ := strconv.Atoi(set.ID)
		if _, err := tx.Exec("insert into ip_sets(id,name,kind,action,cidrs,enabled,created_at,updated_at) values(nullif(?,0),?,?,?,?,?,?,?)", id, set.Name, set.Kind, set.Action, string(cidrs), boolInt(set.Enabled), now, now); err != nil {
			return err
		}
	}
	for _, proxy := range snapshot.HTTPProxies {
		id, _ := strconv.Atoi(proxy.ID)
		targets, _ := json.Marshal(proxy.Targets)
		headers, _ := json.Marshal(proxy.Headers)
		if _, err := tx.Exec(`insert into http_proxies(id,name,host,path,target,targets,headers,health_path,load_balance,enabled,force_tls,websocket,preserve_host,created_at,updated_at)
			values(nullif(?,0),?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, proxy.Name, proxy.Host, proxy.Path, proxy.Target, string(targets), string(headers),
			proxy.HealthPath, proxy.LoadBalance, boolInt(proxy.Enabled), boolInt(proxy.ForceTLS), boolInt(proxy.WebSocket), boolInt(proxy.PreserveHost), now, now); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}
