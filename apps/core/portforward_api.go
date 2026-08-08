package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"porthub/internal/nftables"
)

// portForwards is the CRUD + lifecycle handler for generic port forwards.
func portForwards(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var item portForwardItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		normalizePortForward(&item)
		if err := validatePortForwardItem(item, 0); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now().Format(time.RFC3339)
		allowedJSON, _ := json.Marshal(item.AllowedCIDRs)
		deniedJSON, _ := json.Marshal(item.DeniedCIDRs)
		result, err := db.Exec(`insert into port_forwards(name,node_id,listen_family,listen_address,listen_port_start,listen_port_end,protocol,
			target_family,target_host,target_port_start,target_port_end,forward_mode,snat_mode,enabled,acl_id,allowed_cidrs,denied_cidrs,
			rate_limit_kbps,udp_idle_timeout,health_check,last_status,created_at,updated_at)
			values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			item.Name, item.NodeID, item.ListenFamily, item.ListenAddress, item.ListenPortStart, item.ListenPortEnd, item.Protocol,
			item.TargetFamily, item.TargetHost, item.TargetPortStart, item.TargetPortEnd, item.ForwardMode, item.SNATMode,
			boolInt(item.Enabled), item.ACLID, string(allowedJSON), string(deniedJSON),
			item.RateLimitKbps, item.UDPIdleTimeout, boolInt(item.HealthCheck), "pending", now, now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		id, _ := result.LastInsertId()
		audit(actor(r), "port_forward_create", item.Name)
		writeJSON(w, map[string]any{"ok": true, "id": id})
	case http.MethodPut:
		var item portForwardItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if item.ID < 1 {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		normalizePortForward(&item)
		if err := validatePortForwardItem(item, item.ID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now().Format(time.RFC3339)
		allowedJSON, _ := json.Marshal(item.AllowedCIDRs)
		deniedJSON, _ := json.Marshal(item.DeniedCIDRs)
		_, err := db.Exec(`update port_forwards set name=?,node_id=?,listen_family=?,listen_address=?,listen_port_start=?,listen_port_end=?,protocol=?,
			target_family=?,target_host=?,target_port_start=?,target_port_end=?,forward_mode=?,snat_mode=?,enabled=?,acl_id=?,allowed_cidrs=?,denied_cidrs=?,
			rate_limit_kbps=?,udp_idle_timeout=?,health_check=?,last_status='pending',updated_at=? where id=?`,
			item.Name, item.NodeID, item.ListenFamily, item.ListenAddress, item.ListenPortStart, item.ListenPortEnd, item.Protocol,
			item.TargetFamily, item.TargetHost, item.TargetPortStart, item.TargetPortEnd, item.ForwardMode, item.SNATMode,
			boolInt(item.Enabled), item.ACLID, string(allowedJSON), string(deniedJSON),
			item.RateLimitKbps, item.UDPIdleTimeout, boolInt(item.HealthCheck), now, item.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit(actor(r), "port_forward_update", strconv.Itoa(item.ID))
		writeJSON(w, map[string]any{"ok": true})
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		// Disable + re-apply first so live rules are removed, then delete.
		// Transactional: if re-applying fails we restore the row so the
		// control plane and data plane stay consistent.
		rows, err := db.Query("select enabled from port_forwards where id=?", id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		existed := rows.Next()
		var wasEnabled int
		rows.Scan(&wasEnabled)
		rows.Close()
		if !existed {
			http.Error(w, "forward not found", http.StatusNotFound)
			return
		}
		if _, err := db.Exec("update port_forwards set enabled=0,last_status='disabled' where id=?", id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := applyPortForwards(); err != nil {
			// Roll back the disable so the DB reflects the still-live rule.
			db.Exec("update port_forwards set enabled=?,last_status='applied' where id=?", wasEnabled, id)
			http.Error(w, "delete aborted, re-apply failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		if _, err := db.Exec("delete from port_forwards where id=?", id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit(actor(r), "port_forward_delete", id)
		writeJSON(w, map[string]any{"ok": true})
	default:
		writeJSON(w, loadPortForwards(0))
	}
}

// portForwardToggle enables or disables a rule and re-applies the data plane.
func portForwardToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID      int  `json:"id"`
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID < 1 {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	if _, err := updatePortForwardBatch([]int{req.ID}, req.Enabled, applyPortForwards); err != nil {
		writePortForwardBatchError(w, err)
		return
	}
	audit(actor(r), "port_forward_toggle", fmt.Sprintf("id=%d enabled=%t", req.ID, req.Enabled))
	writeJSON(w, map[string]any{"ok": true})
}

type portForwardBatchRequest struct {
	IDs     []int `json:"ids"`
	Enabled bool  `json:"enabled"`
}

type portForwardBatchInputError struct{ err error }

func (e *portForwardBatchInputError) Error() string { return e.err.Error() }

type portForwardBatchApplyError struct {
	applyErr    error
	rollbackErr error
}

func (e *portForwardBatchApplyError) Error() string {
	if e.rollbackErr != nil {
		return fmt.Sprintf("apply failed: %v; rollback failed: %v", e.applyErr, e.rollbackErr)
	}
	return fmt.Sprintf("apply failed and previous state was restored: %v", e.applyErr)
}

// portForwardBatch atomically enables or disables a set of forwarding rules.
// The database and both data planes are restored if applying the new state fails.
func portForwardBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req portForwardBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	ids, err := normalizePortForwardBatchIDs(req.IDs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	count, err := updatePortForwardBatch(ids, req.Enabled, applyPortForwards)
	if err != nil {
		writePortForwardBatchError(w, err)
		return
	}
	audit(actor(r), "port_forward_batch_toggle", fmt.Sprintf("count=%d enabled=%t", count, req.Enabled))
	writeJSON(w, map[string]any{"ok": true, "count": count, "enabled": req.Enabled})
}

func writePortForwardBatchError(w http.ResponseWriter, err error) {
	switch err.(type) {
	case *portForwardBatchInputError:
		http.Error(w, err.Error(), http.StatusConflict)
	case *portForwardBatchApplyError:
		http.Error(w, err.Error(), http.StatusBadGateway)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func normalizePortForwardBatchIDs(input []int) ([]int, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("select at least one forward")
	}
	if len(input) > 500 {
		return nil, fmt.Errorf("at most 500 forwards can be changed at once")
	}
	seen := make(map[int]bool, len(input))
	ids := make([]int, 0, len(input))
	for _, id := range input {
		if id < 1 {
			return nil, fmt.Errorf("forward id must be positive")
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func updatePortForwardBatch(ids []int, enabled bool, apply func() error) (int, error) {
	selected := make(map[int]bool, len(ids))
	for _, id := range ids {
		selected[id] = true
	}
	all := loadPortForwards(0)
	items := make([]portForwardItem, 0, len(ids))
	for _, item := range all {
		if selected[item.ID] {
			items = append(items, item)
		}
	}
	if len(items) != len(ids) {
		return 0, &portForwardBatchInputError{fmt.Errorf("one or more forwards were not found")}
	}
	if enabled {
		candidates := make([]portForwardItem, len(items))
		for index, item := range items {
			item.Enabled = true
			if err := validatePortForwardItem(item, item.ID); err != nil {
				return 0, &portForwardBatchInputError{fmt.Errorf("forward %q: %w", item.Name, err)}
			}
			candidates[index] = item
		}
		if err := validatePortForwardBatchConflicts(candidates); err != nil {
			return 0, &portForwardBatchInputError{err}
		}
	}

	status := "pending"
	if !enabled {
		status = "disabled"
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	now := time.Now().Format(time.RFC3339)
	for _, item := range items {
		if _, err := tx.Exec("update port_forwards set enabled=?,last_status=?,last_error='',updated_at=? where id=?", boolInt(enabled), status, now, item.ID); err != nil {
			tx.Rollback()
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if err := apply(); err != nil {
		restoreErr := restorePortForwardBatch(items)
		if restoreErr == nil {
			restoreErr = apply()
			if metadataErr := restorePortForwardBatch(items); restoreErr == nil {
				restoreErr = metadataErr
			}
		}
		return 0, &portForwardBatchApplyError{applyErr: err, rollbackErr: restoreErr}
	}
	return len(items), nil
}

func restorePortForwardBatch(items []portForwardItem) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, item := range items {
		if _, err := tx.Exec("update port_forwards set enabled=?,last_status=?,last_error=?,updated_at=? where id=?",
			boolInt(item.Enabled), item.LastStatus, item.LastError, item.UpdatedAt, item.ID); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func validatePortForwardBatchConflicts(items []portForwardItem) error {
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			a, b := items[i], items[j]
			if a.effectiveListenFamily() != b.effectiveListenFamily() {
				continue
			}
			if portRangesOverlap(a.ListenPortStart, a.ListenPortEnd, b.ListenPortStart, b.ListenPortEnd) &&
				protocolsOverlap(a.Protocol, b.Protocol) && listenAddressesOverlap(a.ListenAddress, b.ListenAddress) {
				return fmt.Errorf("forwards %q and %q use the same listening port", a.Name, b.Name)
			}
		}
	}
	return nil
}

// portForwardDuplicate copies an existing rule with a new name.
func portForwardDuplicate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID < 1 {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	source := loadPortForwards(req.ID)
	if len(source) == 0 {
		http.Error(w, "forward not found", http.StatusNotFound)
		return
	}
	item := source[0]
	item.ID = 0
	item.Enabled = false
	item.LastStatus = "pending"
	if strings.TrimSpace(req.Name) != "" {
		item.Name = strings.TrimSpace(req.Name)
	} else {
		item.Name = item.Name + " (copy)"
	}
	normalizePortForward(&item)
	if err := validatePortForwardItem(item, 0); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	now := time.Now().Format(time.RFC3339)
	allowedJSON, _ := json.Marshal(item.AllowedCIDRs)
	deniedJSON, _ := json.Marshal(item.DeniedCIDRs)
	result, err := db.Exec(`insert into port_forwards(name,node_id,listen_family,listen_address,listen_port_start,listen_port_end,protocol,
		target_family,target_host,target_port_start,target_port_end,forward_mode,snat_mode,enabled,acl_id,allowed_cidrs,denied_cidrs,
		rate_limit_kbps,udp_idle_timeout,health_check,last_status,created_at,updated_at)
		values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		item.Name, item.NodeID, item.ListenFamily, item.ListenAddress, item.ListenPortStart, item.ListenPortEnd, item.Protocol,
		item.TargetFamily, item.TargetHost, item.TargetPortStart, item.TargetPortEnd, item.ForwardMode, item.SNATMode,
		boolInt(item.Enabled), item.ACLID, string(allowedJSON), string(deniedJSON),
		item.RateLimitKbps, item.UDPIdleTimeout, boolInt(item.HealthCheck), "pending", now, now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, _ := result.LastInsertId()
	audit(actor(r), "port_forward_duplicate", item.Name)
	writeJSON(w, map[string]any{"ok": true, "id": id})
}

// portForwardStatus reports runtime state: nft presence, relay state, errors.
func portForwardStatus(w http.ResponseWriter, r *http.Request) {
	items := loadPortForwards(0)
	rules := enabledForwardRules(items)
	var nftRules, relayRules []nftables.PortForwardRule
	for _, item := range rules {
		generated := portForwardToRule(item)
		if forwardNeedsRelay(item) {
			relayRules = append(relayRules, generated...)
		} else {
			nftRules = append(nftRules, generated...)
		}
	}
	relayStatus := map[string]any{"running": false, "rules": []any{}, "error": ""}
	if raw := readRelayStatus(); raw != nil {
		relayStatus = raw
	}
	writeJSON(w, map[string]any{
		"total":       len(items),
		"enabled":     len(rules),
		"nft_rules":   len(nftRules),
		"relay_rules": len(relayRules),
		"relay":       relayStatus,
		"items":       items,
	})
}

// forwardNeedsRelay decides whether a rule must run through the relay:
// cross-address-family, domain targets, or explicit relay mode.
func forwardNeedsRelay(item portForwardItem) bool {
	if item.ForwardMode == "relay" {
		return true
	}
	if item.ForwardMode == "nft" {
		return false
	}
	if net.ParseIP(strings.Trim(item.TargetHost, "[]")) == nil {
		return true // domain target requires relay
	}
	return item.effectiveListenFamily() != item.effectiveTargetFamily()
}

func readRelayStatus() map[string]any {
	// Relay writes its status to /var/lib/porthub/relay/status.json (see
	// porthub-relay.service -status flag). Fall back to the legacy path
	// under dataDir for older deployments.
	for _, p := range []string{
		"/var/lib/porthub/relay/status.json",
		filepath.Join(dataDir, "relay", "status.json"),
	} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var out map[string]any
		if json.Unmarshal(data, &out) == nil {
			return out
		}
	}
	return nil
}

// applyPortForwards is the transactional application: compile the merged
// nft rules (core forward + same-family forwards), snapshot the current
// file, apply through netd, then hand relay rules to the relay. On failure
// the previous nft file is restored and the relay is left as-is.
func applyPortForwards() error {
	items := enabledForwardRules(loadPortForwards(0))
	s, err := buildSnapshot("operator")
	if err != nil {
		return err
	}
	// Split rules between nft (same family, IP target) and relay.
	var nftRules []nftables.PortForwardRule
	var nftItems, relayItems []portForwardItem
	for _, item := range items {
		if forwardNeedsRelay(item) {
			relayItems = append(relayItems, item)
		} else {
			nftItems = append(nftItems, item)
			nftRules = append(nftRules, portForwardToRule(item)...)
		}
	}
	// PHASE 1 (prepare): build every candidate and validate before touching
	// any data plane. No side effects in this phase.
	candidate, err := nftables.CompileCoreForwardWithForwards(s, nftRules, coreForwardConfig)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	for _, item := range items {
		if err := validatePortForwardItem(item, item.ID); err != nil {
			return fmt.Errorf("forward %q invalid: %w", item.Name, err)
		}
	}
	relayCfg, err := buildRelayConfig(relayItems)
	if err != nil {
		return fmt.Errorf("relay config: %w", err)
	}
	_ = relayCfg // validated in PHASE 1; applied via applyRelayRules below
	// Snapshot the current candidate for rollback.
	directory := filepath.Join(dataDir, "netd")
	os.MkdirAll(directory, 0750)
	current := filepath.Join(directory, "core-candidate.nft")
	backup := current + ".pf-backup"
	if _, err := os.Stat(current); err == nil {
		data, _ := os.ReadFile(current)
		os.WriteFile(backup, data, 0640)
	}
	// PHASE 2 (commit): apply nft first, then relay. Any failure rolls back
	// everything that was already applied so control and data plane agree.
	if _, err := applyCoreForward(candidate); err != nil {
		if data, err := os.ReadFile(backup); err == nil {
			os.WriteFile(current, data, 0640)
			applyCoreForward(string(data))
		}
		return fmt.Errorf("apply: %w", err)
	}
	if relayErr := applyRelayRules(relayItems); relayErr != nil {
		markForwardStatus(relayItems, "failed", "relay: "+relayErr.Error())
		// Roll back the nft side so both planes stay consistent.
		if data, readErr := os.ReadFile(backup); readErr == nil {
			os.WriteFile(current, data, 0640)
			if _, rbErr := applyCoreForward(string(data)); rbErr == nil {
				markForwardStatus(nftItems, "rolled-back", "relay apply failed: "+relayErr.Error())
			} else {
				markForwardStatus(nftItems, "failed", "relay apply failed and nft rollback failed: "+rbErr.Error())
			}
		}
		return fmt.Errorf("relay rules failed to apply, nft rules rolled back: %w", relayErr)
	}
	// Health check then commit status.
	markForwardStatus(items, "applied", "")
	runForwardHealthChecks(items)
	return nil
}

// buildRelayConfig renders the relay configuration JSON without applying it.
// Kept separate from applyRelayRules so PHASE 1 can validate before commit.
func buildRelayConfig(items []portForwardItem) ([]byte, error) {
	cfg := relayConfig{Rules: []relayRule{}}
	for _, item := range items {
		segments := splitForwardByACL(item)
		for _, seg := range segments {
			allowed, denied := resolveForwardACL(item, seg.UseACL)
			cfg.Rules = append(cfg.Rules, relayRule{
				ID:              item.ID,
				Name:            item.Name,
				ListenFamily:    item.effectiveListenFamily(),
				ListenAddress:   item.ListenAddress,
				ListenPortStart: seg.ListenStart,
				ListenPortEnd:   seg.ListenEnd,
				Protocol:        item.Protocol,
				TargetHost:      item.TargetHost,
				TargetPortStart: seg.TargetStart,
				TargetPortEnd:   seg.TargetEnd,
				AllowedCIDRs:    allowed,
				DeniedCIDRs:     denied,
				RateLimitKbps:   item.RateLimitKbps,
				UDPIdleTimeout:  item.UDPIdleTimeout,
			})
		}
	}
	return json.Marshal(cfg)
}

func markForwardStatus(items []portForwardItem, status, errMsg string) {
	if len(items) == 0 {
		return
	}
	for _, item := range items {
		db.Exec("update port_forwards set last_status=?,last_error=? where id=?", status, errMsg, item.ID)
	}
}

// runForwardHealthChecks probes TCP targets of enabled rules with
// health_check enabled and records reachability in last_error.
func runForwardHealthChecks(items []portForwardItem) {
	for _, item := range items {
		if !item.HealthCheck || item.Protocol == "udp" {
			continue
		}
		target := net.JoinHostPort(strings.Trim(item.TargetHost, "[]"), strconv.Itoa(item.TargetPortStart))
		conn, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err == nil {
			conn.Close()
			db.Exec("update port_forwards set last_error='' where id=?", item.ID)
		} else {
			db.Exec("update port_forwards set last_error=? where id=?", "health: "+err.Error(), item.ID)
		}
	}
}

// portForwardApply manually re-applies all enabled rules and reports the
// per-rule outcome, including failure reasons.
func portForwardApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	audit(actor(r), "port_forward_apply", "all")
	if err := applyPortForwards(); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// applyRelayRules writes relay configuration through netd.
func applyRelayRules(items []portForwardItem) error {
	if len(items) == 0 {
		return applyRelayConfig(nil)
	}
	return applyRelayConfig(items)
}
