package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"porthub/internal/auth"
	"porthub/internal/nftables"
	"porthub/internal/snapshots"
	"strconv"
	"strings"
	"time"
)

type genericItem struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Data        string `json:"data"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/health", health)
	mux.HandleFunc("/api/integrations/airsim", requireAuth(airsimIntegrationStatus))
	mux.HandleFunc("/api/ready", readiness)
	mux.HandleFunc("/api/openapi.yaml", openAPI)
	mux.HandleFunc("/api/login", login)
	mux.HandleFunc("/api/agents/register", agentRegister)
	mux.HandleFunc("/api/agents/heartbeat", agentHeartbeat)
	mux.HandleFunc("/api/session", requireAuth(sessionStatus))
	mux.HandleFunc("/api/agents/enrollments", requireAuth(agentEnrollments))
	mux.HandleFunc("/api/logout", requireAuth(logout))
	mux.HandleFunc("/api/password/change", requireAuth(changePassword))
	mux.HandleFunc("/api/status", requireAuth(status))
	mux.HandleFunc("/api/edge/status", requireAuth(edgeStatus))
	mux.HandleFunc("/api/nodes/status", requireAuth(nodeStatus))
	mux.HandleFunc("/api/nodes/discovery", requireAuth(nodeDiscovery))
	mux.HandleFunc("/api/lan-scan", requireAuth(lanScan))
	mux.HandleFunc("/api/edge/metrics", requireAuth(edgeMetrics))
	mux.HandleFunc("/api/metrics", requireAuth(coreMetricsHandler))
	mux.HandleFunc("/api/http-proxies/health", requireAuth(proxyBackendHealth))
	mux.HandleFunc("/api/traffic/snapshot", requireAuth(trafficSnapshot))
	mux.HandleFunc("/api/traffic/recent", requireAuth(trafficRecent))
	mux.HandleFunc("/api/traffic/rules", requireAuth(trafficRulesRecent))
	mux.HandleFunc("/api/traffic/rank", requireAuth(trafficRank))
	mux.HandleFunc("/api/traffic/trend", requireAuth(trafficTrend))
	mux.HandleFunc("/api/traffic/public-sources", requireAuth(trafficPublicSources))
	mux.HandleFunc("/api/alerts", requireAuth(systemAlerts))
	mux.HandleFunc("/api/monitor/stream", requireAuth(monitorStream))
	mux.HandleFunc("/api/ai/draft", requireAuth(aiDraft))
	mux.HandleFunc("/api/audit", requireAuth(auditLog))
	mux.HandleFunc("/api/mappings", requireAuth(mappings))
	mux.HandleFunc("/api/mappings/bulk", requireAuth(mappingBulk))
	mux.HandleFunc("/api/mappings/export", requireAuth(mappingExport))
	mux.HandleFunc("/api/mappings/import", requireAuth(mappingImport))
	mux.HandleFunc("/api/mappings/conflicts", requireAuth(mappingConflicts))
	mux.HandleFunc("/api/snapshot", requireAuth(snapshot))
	mux.HandleFunc("/api/snapshots", requireAuth(snapshotHistory))
	mux.HandleFunc("/api/snapshots/rollback", requireAuth(snapshotRollback))
	mux.HandleFunc("/api/nft/preview", requireAuth(nftPreview))
	mux.HandleFunc("/api/deploy", requireAuth(deploySnapshot))
	mux.HandleFunc("/api/http-proxies", requireAuth(httpProxies))
	mux.HandleFunc("/api/domains", requireAuth(domains))
	mux.HandleFunc("/api/ddns/providers", requireAuth(ddnsProviders))
	mux.HandleFunc("/api/ddns/provider-schema", requireAuth(providerSchemaHandler))
	mux.HandleFunc("/api/ddns/interfaces", requireAuth(ddnsInterfacesHandler))
	mux.HandleFunc("/api/ddns/records", requireAuth(ddnsRecords))
	mux.HandleFunc("/api/ddns/sync", requireAuth(ddnsSync))
	mux.HandleFunc("/api/certificates", requireAuth(certificates))
	mux.HandleFunc("/api/certificates/plan", requireAuth(certificatePlan))
	mux.HandleFunc("/api/certificates/acme/prepare", requireAuth(certificatePrepare))
	mux.HandleFunc("/api/certificates/acme/issue", requireAuth(certificateACMEIssue))
	mux.HandleFunc("/api/certificates/acme/status", requireAuth(certificateACMEStatus))
	mux.HandleFunc("/api/certificates/import", requireAuth(certificateImport))
	mux.HandleFunc("/api/certificates/deploy", requireAuth(certificateDeploy))
	mux.HandleFunc("/api/wireguard/peers", requireAuth(wireGuardPeers))
	mux.HandleFunc("/api/wireguard/peers/deploy", requireAuth(wireGuardPeersDeploy))
	mux.HandleFunc("/api/wireguard/status", requireAuth(wireGuardStatusProxy))
	mux.HandleFunc("/api/port-forwards", requireAuth(portForwards))
	mux.HandleFunc("/api/port-forwards/toggle", requireAuth(portForwardToggle))
	mux.HandleFunc("/api/port-forwards/batch", requireAuth(portForwardBatch))
	mux.HandleFunc("/api/port-forwards/duplicate", requireAuth(portForwardDuplicate))
	mux.HandleFunc("/api/port-forwards/status", requireAuth(portForwardStatus))
	mux.HandleFunc("/api/port-forwards/test", requireAuth(testForwardTarget))
	mux.HandleFunc("/api/port-forwards/apply", requireAuth(portForwardApply))
	mux.HandleFunc("/api/qx/services", requireAuth(qxServices))
	mux.HandleFunc("/api/managed-services", requireAuth(managedServices))
	mux.HandleFunc("/api/backups", requireAuth(backups))
	mux.HandleFunc("/api/backups/restore/plan", requireAuth(backupRestorePlan))
	mux.HandleFunc("/api/backups/download", requireAuth(backupDownload))
	mux.HandleFunc("/api/ip-sets", requireAuth(ipSets))
	mux.HandleFunc("/api/ip-sets/import", requireAuth(ipSetImport))
	mux.HandleFunc("/api/ip-feeds", requireAuth(ipFeeds))
	mux.HandleFunc("/api/ip-feeds/sync", requireAuth(ipFeedSync))
	mux.HandleFunc("/api/updates/status", requireAuth(updatesStatus))
	mux.HandleFunc("/api/updates/check", requireAuth(updatesCheck))
	mux.HandleFunc("/api/updates/stage", requireAuth(updatesStage))
	mux.HandleFunc("/api/resources", requireAuth(genericCRUD("resources")))
	mux.HandleFunc("/api/services", requireAuth(genericCRUD("services")))
	mux.HandleFunc("/api/groups", requireAuth(genericCRUD("mapping_groups")))
	mux.HandleFunc("/api/acls", requireAuth(genericCRUD("acls")))
	mux.HandleFunc("/api/acl-rules", requireAuth(aclRules))
	mux.HandleFunc("/api/templates", requireAuth(genericCRUD("templates")))
	mux.HandleFunc("/api/templates/builtin", requireAuth(builtinTemplates))
	mux.HandleFunc("/api/templates/apply", requireAuth(applyTemplate))
	mux.HandleFunc("/api/webhooks", requireAuth(genericCRUD("webhooks")))
	mux.HandleFunc("/api/tokens", requireAuth(tokens))
	mux.HandleFunc("/api/users", requireAuth(users))
	mux.HandleFunc("/api/users/reset-password", requireAuth(userResetPassword))
	mux.HandleFunc("/api/users/reset-totp", requireAuth(userResetTOTP))
	mux.HandleFunc("/", frontendHandler(frontendDir))
}

func status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"edge": "online", "core": "online", "wg": "wg-porthub", "time": time.Now()})
}

func edgeStatus(w http.ResponseWriter, r *http.Request) {
	res, err := getEdgeJSON("/api/status")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, res)
}

func edgeMetrics(w http.ResponseWriter, r *http.Request) {
	res, err := getEdgeJSON("/api/metrics")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	audit(actor(r), "edge_metrics_read", "")
	writeJSON(w, redactMetricsSourceIPs(res, canViewExactSourceIP(r)))
}

func proxyBackendHealth(w http.ResponseWriter, r *http.Request) {
	res, err := getEdgeJSON("/api/proxy-health")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, res)
}

func mappings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var m snapshots.Mapping
		json.NewDecoder(r.Body).Decode(&m)
		normalizeMapping(&m)
		all := append(loadMappings(0), m)
		if err := snapshots.ValidateMappings(all); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, err := insertMapping(db, m, actor(r), false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit(actor(r), "mapping_create", m.Name)
		w.WriteHeader(http.StatusCreated)
		return
	}
	if r.Method == http.MethodPut {
		var m snapshots.Mapping
		json.NewDecoder(r.Body).Decode(&m)
		id, err := strconv.Atoi(m.ID)
		if err != nil || id < 1 {
			http.Error(w, "valid id required", http.StatusBadRequest)
			return
		}
		normalizeMapping(&m)
		all := append(loadMappings(id), m)
		if err := snapshots.ValidateMappings(all); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, err = updateStoredMapping(db, id, m)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit(actor(r), "mapping_update", m.ID)
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	if r.Method == http.MethodDelete {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		db.Exec("delete from mappings where id=?", id)
		audit(actor(r), "mapping_delete", id)
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	listMappings(w)
}

func listMappings(w http.ResponseWriter) {
	writeJSON(w, loadMappings(0))
}

func loadMappings(excludeID int) []snapshots.Mapping {
	rows, _ := db.Query(`select id,name,coalesce(description,''),coalesce(tags,''),coalesce(resource_id,''),coalesce(service_id,''),coalesce(group_id,''),coalesce(edge_id,''),
		coalesce(public_ip,''),coalesce(target_node_id,''),target_ip,public_start,public_end,target_start,target_end,proto,enabled,coalesce(acl_ids,''),
		coalesce(rate_limit_kbps,0),coalesce(connection_limit,0),coalesce(log_level,'info'),coalesce(source_mode,'compat'),coalesce(created_by,''),
		coalesce(created_at,''),coalesce(updated_at,'') from mappings order by id`)
	defer rows.Close()
	var out []snapshots.Mapping
	for rows.Next() {
		var m snapshots.Mapping
		var id, en int
		var aclIDs, tags string
		rows.Scan(&id, &m.Name, &m.Description, &tags, &m.ResourceID, &m.ServiceID, &m.GroupID, &m.EdgeID, &m.PublicIP, &m.TargetNodeID, &m.TargetIP,
			&m.PublicStart, &m.PublicEnd, &m.TargetStart, &m.TargetEnd, &m.Protocol, &en, &aclIDs, &m.RateLimitKbps, &m.ConnectionLimit,
			&m.LogLevel, &m.SourceMode, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt)
		if id == excludeID {
			continue
		}
		m.ID = strconv.Itoa(id)
		m.Enabled = en == 1
		json.Unmarshal([]byte(aclIDs), &m.ACLIDs)
		json.Unmarshal([]byte(tags), &m.Tags)
		out = append(out, m)
	}
	return out
}

func snapshot(w http.ResponseWriter, r *http.Request) {
	s, err := buildSnapshot(actor(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(actor(r), "snapshot_generate", strconv.FormatInt(s.Version, 10))
	writeJSON(w, s)
}

func buildSnapshot(operator string) (snapshots.Snapshot, error) {
	ms := loadMappings(0)
	if err := snapshots.ValidateMappings(ms); err != nil {
		return snapshots.Snapshot{}, err
	}
	rules := loadACLRules(0)
	if err := snapshots.ValidateACLRules(rules); err != nil {
		return snapshots.Snapshot{}, err
	}
	if err := snapshots.ValidateACLRefs(ms, rules); err != nil {
		return snapshots.Snapshot{}, err
	}
	ipSets := loadIPSets(0)
	if err := snapshots.ValidateIPSets(ipSets); err != nil {
		return snapshots.Snapshot{}, err
	}
	proxies := loadHTTPProxies(0)
	if err := snapshots.ValidateHTTPProxies(proxies); err != nil {
		return snapshots.Snapshot{}, err
	}
	return snapshots.Sign(snapshots.Snapshot{Version: time.Now().UnixNano(), CreatedAt: time.Now().UTC(), Operator: operator, Mappings: ms, ACLRules: rules, IPSets: ipSets, HTTPProxies: proxies}, priv)
}

func mappingConflicts(w http.ResponseWriter, r *http.Request) {
	mappings := loadMappings(0)
	err := snapshots.ValidateMappings(mappings)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	conflicts, err := checkEdgePortAvailability(mappings)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "Edge port scan failed: " + err.Error()})
		return
	}
	if len(conflicts) > 0 {
		writeJSON(w, map[string]any{"ok": false, "error": strings.Join(conflicts, "; "), "conflicts": conflicts})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "conflicts": []string{}})
}

func nftPreview(w http.ResponseWriter, r *http.Request) {
	s, err := buildSnapshot(actor(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rules, err := nftables.Compile(s, "wg-porthub")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	coreRules, err := compileCoreForward(s)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"version": s.Version, "nft": rules, "core_nft": coreRules})
}

func genericCRUD(table string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var item genericItem
			if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
				http.Error(w, "请求数据无效", http.StatusBadRequest)
				return
			}
			if duplicate, err := genericDuplicate(table, item, 0); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			} else if duplicate {
				http.Error(w, "相同资源或服务已经存在", http.StatusConflict)
				return
			}
			now := time.Now().Format(time.RFC3339)
			_, err := db.Exec("insert into "+table+"(name,description,data,enabled,created_at,updated_at) values(?,?,?,?,?,?)", item.Name, item.Description, item.Data, boolInt(item.Enabled), now, now)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			audit(actor(r), table+"_create", item.Name)
			w.WriteHeader(http.StatusCreated)
		case http.MethodPut:
			var item genericItem
			if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
				http.Error(w, "请求数据无效", http.StatusBadRequest)
				return
			}
			if item.ID == 0 {
				http.Error(w, "id required", http.StatusBadRequest)
				return
			}
			if duplicate, err := genericDuplicate(table, item, item.ID); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			} else if duplicate {
				http.Error(w, "相同资源或服务已经存在", http.StatusConflict)
				return
			}
			now := time.Now().Format(time.RFC3339)
			db.Exec("update "+table+" set name=?,description=?,data=?,enabled=?,updated_at=? where id=?", item.Name, item.Description, item.Data, boolInt(item.Enabled), now, item.ID)
			audit(actor(r), table+"_update", strconv.Itoa(item.ID))
			writeJSON(w, map[string]any{"ok": true})
		case http.MethodDelete:
			id := r.URL.Query().Get("id")
			if id == "" {
				http.Error(w, "id required", http.StatusBadRequest)
				return
			}
			db.Exec("delete from "+table+" where id=?", id)
			audit(actor(r), table+"_delete", id)
			writeJSON(w, map[string]any{"ok": true})
		default:
			rows, _ := db.Query("select id,name,description,data,enabled,created_at,updated_at from " + table + " order by id desc")
			defer rows.Close()
			writeJSON(w, scanGeneric(rows))
		}
	}
}

func genericDuplicate(table string, item genericItem, excludeID int) (bool, error) {
	if table != "resources" && table != "services" {
		return false, nil
	}
	var candidate map[string]any
	if err := json.Unmarshal([]byte(item.Data), &candidate); err != nil {
		return false, fmt.Errorf("data 必须是 JSON 对象")
	}
	rows, err := db.Query("select id,data from " + table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var raw string
		if rows.Scan(&id, &raw) != nil || id == excludeID {
			continue
		}
		var existing map[string]any
		if json.Unmarshal([]byte(raw), &existing) != nil {
			continue
		}
		if table == "resources" && sameString(candidate, existing, "ip") {
			return true, nil
		}
		if table == "services" && sameString(candidate, existing, "ip") && sameNumber(candidate, existing, "port") && sameString(candidate, existing, "protocol") {
			return true, nil
		}
	}
	return false, rows.Err()
}

func sameString(left, right map[string]any, key string) bool {
	a, aok := left[key].(string)
	b, bok := right[key].(string)
	return aok && bok && strings.TrimSpace(a) != "" && strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func sameNumber(left, right map[string]any, key string) bool {
	a, aok := left[key].(float64)
	b, bok := right[key].(float64)
	return aok && bok && a == b && a > 0
}

func tokens(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		db.Exec("update api_tokens set revoked=1 where id=?", id)
		audit(actor(r), "api_token_revoke", id)
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	if r.Method != http.MethodPost {
		rows, _ := db.Query("select id,name,prefix,role,created_at,last_used_at,revoked from api_tokens order by id desc")
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var id, revoked int
			var name, prefix, role, created, last sql.NullString
			rows.Scan(&id, &name, &prefix, &role, &created, &last, &revoked)
			out = append(out, map[string]any{"id": id, "name": name.String, "prefix": prefix.String, "role": role.String, "created_at": created.String, "last_used_at": last.String, "revoked": revoked == 1})
		}
		writeJSON(w, out)
		return
	}
	var x struct{ Name, Role string }
	if err := json.NewDecoder(r.Body).Decode(&x); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if x.Role == "" {
		x.Role = "operator"
	}
	if err := validateRole(x.Role); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	currentRole, _ := r.Context().Value(roleKey).(string)
	if roleValue(x.Role) > roleValue(currentRole) {
		http.Error(w, "cannot create token with higher role than current actor", http.StatusForbidden)
		return
	}
	raw := "ph_" + auth.RandomPassword()
	prefix := raw[:10]
	now := time.Now().Format(time.RFC3339)
	if _, err := db.Exec("insert into api_tokens(name,token_hash,prefix,role,created_at,revoked) values(?,?,?,?,?,0)", x.Name, hashToken(raw), prefix, x.Role, now); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audit(actor(r), "api_token_create", x.Name)
	writeJSON(w, map[string]any{"token": raw, "prefix": prefix})
}

func scanGeneric(rows *sql.Rows) []genericItem {
	var out []genericItem
	for rows.Next() {
		var item genericItem
		var enabled int
		rows.Scan(&item.ID, &item.Name, &item.Description, &item.Data, &enabled, &item.CreatedAt, &item.UpdatedAt)
		item.Enabled = enabled == 1
		out = append(out, item)
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func normalizeMapping(m *snapshots.Mapping) {
	m.Name = strings.TrimSpace(m.Name)
	m.Description = strings.TrimSpace(m.Description)
	m.PublicIP = strings.TrimSpace(m.PublicIP)
	m.TargetIP = strings.TrimSpace(m.TargetIP)
	if m.Protocol == "" {
		m.Protocol = snapshots.TCP
	}
	if m.PublicEnd == 0 {
		m.PublicEnd = m.PublicStart
	}
	if m.TargetEnd == 0 {
		m.TargetEnd = m.TargetStart
	}
	if m.ACLID != "" && len(m.ACLIDs) == 0 {
		m.ACLIDs = []string{m.ACLID}
	}
	if m.LogLevel == "" {
		m.LogLevel = "info"
	}
	if m.SourceMode == "" {
		m.SourceMode = "compat"
	}
	seenTags := map[string]bool{}
	cleanTags := m.Tags[:0]
	for _, tag := range m.Tags {
		tag = strings.TrimSpace(tag)
		if tag != "" && !seenTags[tag] {
			seenTags[tag] = true
			cleanTags = append(cleanTags, tag)
		}
	}
	m.Tags = cleanTags
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
