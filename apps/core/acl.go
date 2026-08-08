package main

import (
	"encoding/json"
	"net"
	"net/http"
	"porthub/internal/snapshots"
	"strconv"
	"strings"
	"time"
)

func aclRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var rule snapshots.ACLRule
		if json.NewDecoder(r.Body).Decode(&rule) != nil {
			http.Error(w, "invalid ACL request", http.StatusBadRequest)
			return
		}
		normalizeACLRule(&rule)
		if err := snapshots.ValidateACLRules([]snapshots.ACLRule{rule}); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now().Format(time.RFC3339)
		protocols, _ := json.Marshal(rule.Protocols)
		nodes, _ := json.Marshal(rule.NodeIDs)
		services, _ := json.Marshal(rule.ServiceIDs)
		groups, _ := json.Marshal(rule.GroupIDs)
		weekdays, _ := json.Marshal(rule.Weekdays)
		_, err := db.Exec(`insert into acl_rules(name,action,cidr,enabled,protocols,port_start,port_end,node_ids,service_ids,group_ids,weekdays,start_time,end_time,timezone,created_at,updated_at)
			values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, rule.Name, string(rule.Action), rule.CIDR, boolInt(rule.Enabled), string(protocols), rule.PortStart,
			rule.PortEnd, string(nodes), string(services), string(groups), string(weekdays), rule.StartTime, rule.EndTime, rule.Timezone, now, now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit(actor(r), "acl_rule_create", rule.Name)
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		var rule snapshots.ACLRule
		if json.NewDecoder(r.Body).Decode(&rule) != nil {
			http.Error(w, "invalid ACL request", http.StatusBadRequest)
			return
		}
		id, err := strconv.Atoi(rule.ID)
		if err != nil || id < 1 {
			http.Error(w, "valid id required", http.StatusBadRequest)
			return
		}
		normalizeACLRule(&rule)
		if err := snapshots.ValidateACLRules([]snapshots.ACLRule{rule}); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		protocols, _ := json.Marshal(rule.Protocols)
		nodes, _ := json.Marshal(rule.NodeIDs)
		services, _ := json.Marshal(rule.ServiceIDs)
		groups, _ := json.Marshal(rule.GroupIDs)
		weekdays, _ := json.Marshal(rule.Weekdays)
		db.Exec(`update acl_rules set name=?,action=?,cidr=?,enabled=?,protocols=?,port_start=?,port_end=?,node_ids=?,service_ids=?,group_ids=?,weekdays=?,start_time=?,end_time=?,timezone=?,updated_at=? where id=?`,
			rule.Name, string(rule.Action), rule.CIDR, boolInt(rule.Enabled), string(protocols), rule.PortStart, rule.PortEnd, string(nodes), string(services),
			string(groups), string(weekdays), rule.StartTime, rule.EndTime, rule.Timezone, time.Now().Format(time.RFC3339), id)
		audit(actor(r), "acl_rule_update", rule.ID)
		writeJSON(w, map[string]any{"ok": true})
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		db.Exec("delete from acl_rules where id=?", id)
		audit(actor(r), "acl_rule_delete", id)
		writeJSON(w, map[string]any{"ok": true})
	default:
		writeJSON(w, loadACLRules(0))
	}
}

func loadACLRules(excludeID int) []snapshots.ACLRule {
	rows, _ := db.Query(`select id,name,action,cidr,enabled,coalesce(protocols,''),coalesce(port_start,0),coalesce(port_end,0),coalesce(node_ids,''),
		coalesce(service_ids,''),coalesce(group_ids,''),coalesce(weekdays,''),coalesce(start_time,''),coalesce(end_time,''),coalesce(timezone,'') from acl_rules order by id`)
	defer rows.Close()
	var out []snapshots.ACLRule
	for rows.Next() {
		var id, enabled int
		var rule snapshots.ACLRule
		var protocols, nodes, services, groups, weekdays string
		rows.Scan(&id, &rule.Name, &rule.Action, &rule.CIDR, &enabled, &protocols, &rule.PortStart, &rule.PortEnd, &nodes, &services, &groups,
			&weekdays, &rule.StartTime, &rule.EndTime, &rule.Timezone)
		if id == excludeID {
			continue
		}
		rule.ID = strconv.Itoa(id)
		rule.Enabled = enabled == 1
		_ = json.Unmarshal([]byte(protocols), &rule.Protocols)
		_ = json.Unmarshal([]byte(nodes), &rule.NodeIDs)
		_ = json.Unmarshal([]byte(services), &rule.ServiceIDs)
		_ = json.Unmarshal([]byte(groups), &rule.GroupIDs)
		_ = json.Unmarshal([]byte(weekdays), &rule.Weekdays)
		out = append(out, rule)
	}
	return out
}

func normalizeACLRule(rule *snapshots.ACLRule) {
	rule.Name = strings.TrimSpace(rule.Name)
	rule.CIDR = strings.TrimSpace(rule.CIDR)
	if ip := net.ParseIP(rule.CIDR); ip != nil {
		if ip.To4() != nil {
			rule.CIDR = ip.String() + "/32"
		} else {
			rule.CIDR = ip.String() + "/128"
		}
	} else if strings.Contains(rule.CIDR, "-") {
		parts := strings.Split(rule.CIDR, "-")
		if len(parts) == 2 {
			rule.CIDR = strings.TrimSpace(parts[0]) + "-" + strings.TrimSpace(parts[1])
		}
	}
	if rule.PortStart > 0 && rule.PortEnd == 0 {
		rule.PortEnd = rule.PortStart
	}
	if rule.StartTime != "" && rule.Timezone == "" {
		rule.Timezone = "Asia/Shanghai"
	}
}
