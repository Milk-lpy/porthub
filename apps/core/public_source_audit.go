package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// publicSourceAudit stores a minute bucket for a source/mapping tuple. Edge
// sends a conntrack snapshot, so storing one row per snapshot would grow too
// quickly on a busy VPS. The bucket keeps the first/last observation and the
// maximum conntrack byte counter for that minute.
type publicSourceAudit struct {
	ID             int    `json:"id"`
	ObservedMinute string `json:"observed_minute"`
	FirstSeenAt    string `json:"first_seen_at"`
	LastSeenAt     string `json:"last_seen_at"`
	EdgeVersion    string `json:"edge_version"`
	SourceIP       string `json:"source_ip"`
	SourceIPMasked string `json:"source_ip_masked"`
	MappingID      string `json:"mapping_id"`
	Mapping        string `json:"mapping"`
	Protocol       string `json:"protocol"`
	PublicPort     int    `json:"public_port"`
	Target         string `json:"target"`
	State          string `json:"state"`
	Bytes          uint64 `json:"bytes"`
	Observations   uint64 `json:"observations"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type publicSourceSummary struct {
	SourceIP       string `json:"source_ip"`
	SourceIPMasked string `json:"source_ip_masked"`
	Mappings       int    `json:"mappings"`
	Bytes          uint64 `json:"bytes"`
	Observations   uint64 `json:"observations"`
	LastSeenAt     string `json:"last_seen_at"`
}

type publicSourceAuditResponse struct {
	Records       []publicSourceAudit   `json:"records"`
	Summary       []publicSourceSummary `json:"summary"`
	Total         int                   `json:"total"`
	RetentionDays int                   `json:"retention_days"`
	ExactSourceIP bool                  `json:"exact_source_ip"`
}

type publicSourceAuditFilter struct {
	Where []string
	Args  []any
}

func storePublicSourceAudits(edgeVersion string, metrics map[string]any) error {
	items, ok := metrics["connection_summary"].([]any)
	if !ok || len(items) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	for _, item := range items {
		connection, ok := item.(map[string]any)
		if !ok {
			continue
		}
		sourceIP, ok := normalizePublicSourceIP(jsonValueString(connection["source_ip"]))
		if !ok {
			// A private/loopback source is not an Internet source audit record.
			continue
		}
		observedAt := parseSourceAuditTime(jsonValueString(connection["observed_at"]))
		if observedAt.IsZero() {
			observedAt = now
		}
		observedAt = observedAt.UTC()
		protocol := strings.ToLower(strings.TrimSpace(jsonValueString(connection["protocol"])))
		publicPort := int(jsonValueUint(connection["public_port"]))
		if (protocol != "tcp" && protocol != "udp") || publicPort < 1 || publicPort > 65535 {
			continue
		}
		observedMinute := observedAt.Truncate(time.Minute).Format(time.RFC3339)
		observedText := observedAt.Format(time.RFC3339)
		_, err = tx.Exec(`insert into public_source_audits(
			observed_minute,first_seen_at,last_seen_at,edge_version,source_ip,
			mapping_id,mapping,protocol,public_port,target,state,bytes,observations,timeout_seconds
		) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		on conflict(observed_minute,source_ip,mapping_id,protocol,public_port) do update set
			last_seen_at=excluded.last_seen_at,
			edge_version=excluded.edge_version,
			mapping=excluded.mapping,
			target=excluded.target,
			state=excluded.state,
			bytes=max(public_source_audits.bytes,excluded.bytes),
			observations=public_source_audits.observations+1,
			timeout_seconds=excluded.timeout_seconds`,
			observedMinute,
			observedText,
			observedText,
			edgeVersion,
			sourceIP,
			jsonValueString(connection["mapping_id"]),
			jsonValueString(connection["mapping"]),
			protocol,
			publicPort,
			jsonValueString(connection["target"]),
			jsonValueString(connection["state"]),
			jsonValueUint(connection["bytes"]),
			1,
			int(jsonValueUint(connection["timeout_seconds"])),
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func normalizePublicSourceIP(raw string) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil || !isPublicSourceIP(ip) {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), true
	}
	return ip.String(), true
}

func isPublicSourceIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return false
	}
	// Go's net.IP.IsPrivate intentionally covers RFC1918/ULA, not the
	// carrier-grade NAT range. It must not be counted as an Internet client.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return false
	}
	return ip.IsGlobalUnicast()
}

func parseSourceAuditTime(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func maskSourceIP(raw string) string {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "***"
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.xxx.xxx", v4[0], v4[1])
	}
	v6 := ip.To16()
	if v6 == nil {
		return "***"
	}
	return fmt.Sprintf("%x:%x:%x:%x:****",
		binary.BigEndian.Uint16(v6[0:2]),
		binary.BigEndian.Uint16(v6[2:4]),
		binary.BigEndian.Uint16(v6[4:6]),
		binary.BigEndian.Uint16(v6[6:8]),
	)
}

func canViewExactSourceIP(r *http.Request) bool {
	role, _ := r.Context().Value(roleKey).(string)
	return roleValue(role) >= roleOperator
}

func sourceIPForViewer(raw string, exact bool) string {
	if exact {
		return raw
	}
	return maskSourceIP(raw)
}

func buildPublicSourceAuditFilter(r *http.Request) (publicSourceAuditFilter, error) {
	filter := publicSourceAuditFilter{Where: []string{"1=1"}}
	if raw := strings.TrimSpace(r.URL.Query().Get("source_ip")); raw != "" {
		sourceIP, ok := normalizePublicSourceIP(raw)
		if !ok {
			return filter, fmt.Errorf("source_ip must be a public IPv4 or IPv6 address")
		}
		filter.Where = append(filter.Where, "source_ip=?")
		filter.Args = append(filter.Args, sourceIP)
	}
	if mappingID := strings.TrimSpace(r.URL.Query().Get("mapping_id")); mappingID != "" {
		if len(mappingID) > 128 {
			return filter, fmt.Errorf("mapping_id is too long")
		}
		filter.Where = append(filter.Where, "(mapping_id=? or lower(mapping) like lower(?))")
		filter.Args = append(filter.Args, mappingID, "%"+mappingID+"%")
	}
	if protocol := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("protocol"))); protocol != "" {
		if protocol != "tcp" && protocol != "udp" {
			return filter, fmt.Errorf("protocol must be tcp or udp")
		}
		filter.Where = append(filter.Where, "protocol=?")
		filter.Args = append(filter.Args, protocol)
	}
	for _, item := range []struct {
		name string
		col  string
	}{
		{name: "from", col: "last_seen_at >= ?"},
		{name: "to", col: "last_seen_at < ?"},
	} {
		raw := strings.TrimSpace(r.URL.Query().Get(item.name))
		if raw == "" {
			continue
		}
		parsed, err := parseFilterTime(raw, item.name == "to")
		if err != nil {
			return filter, err
		}
		filter.Where = append(filter.Where, item.col)
		filter.Args = append(filter.Args, parsed)
	}
	return filter, nil
}

func parseFilterTime(raw string, exclusiveEnd bool) (string, error) {
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		parsed, err = time.Parse("2006-01-02", raw)
		if err == nil && exclusiveEnd {
			parsed = parsed.Add(24 * time.Hour)
		}
	}
	if err != nil {
		return "", fmt.Errorf("invalid time filter %q", raw)
	}
	return parsed.UTC().Format(time.RFC3339), nil
}

func trafficPublicSources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filter, err := buildPublicSourceAuditFilter(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	where := strings.Join(filter.Where, " and ")
	limit := boundedLimit(r, 100)
	exact := canViewExactSourceIP(r)

	var total int
	if err := db.QueryRow("select count(*) from public_source_audits where "+where, filter.Args...).Scan(&total); err != nil {
		http.Error(w, "public source audit unavailable", http.StatusInternalServerError)
		return
	}

	args := append(append([]any{}, filter.Args...), limit)
	rows, err := db.Query(`select id,observed_minute,first_seen_at,last_seen_at,coalesce(edge_version,''),source_ip,
		coalesce(mapping_id,''),coalesce(mapping,''),coalesce(protocol,''),coalesce(public_port,0),coalesce(target,''),
		coalesce(state,''),coalesce(bytes,0),coalesce(observations,0),coalesce(timeout_seconds,0)
		from public_source_audits where `+where+` order by last_seen_at desc,id desc limit ?`, args...)
	if err != nil {
		http.Error(w, "public source audit unavailable", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	records := make([]publicSourceAudit, 0)
	for rows.Next() {
		var record publicSourceAudit
		var sourceIP string
		var bytes, observations int64
		if err := rows.Scan(&record.ID, &record.ObservedMinute, &record.FirstSeenAt, &record.LastSeenAt, &record.EdgeVersion, &sourceIP,
			&record.MappingID, &record.Mapping, &record.Protocol, &record.PublicPort, &record.Target, &record.State,
			&bytes, &observations, &record.TimeoutSeconds); err != nil {
			http.Error(w, "public source audit unavailable", http.StatusInternalServerError)
			return
		}
		if bytes > 0 {
			record.Bytes = uint64(bytes)
		}
		if observations > 0 {
			record.Observations = uint64(observations)
		}
		record.SourceIP = sourceIPForViewer(sourceIP, exact)
		record.SourceIPMasked = maskSourceIP(sourceIP)
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "public source audit unavailable", http.StatusInternalServerError)
		return
	}

	summaryRows, err := db.Query(`select source_ip,count(distinct mapping_id),coalesce(sum(bytes),0),coalesce(sum(observations),0),max(last_seen_at)
		from public_source_audits where `+where+` group by source_ip order by sum(bytes) desc,last_seen_at desc limit 20`, filter.Args...)
	if err != nil {
		http.Error(w, "public source audit unavailable", http.StatusInternalServerError)
		return
	}
	defer summaryRows.Close()
	summary := make([]publicSourceSummary, 0)
	for summaryRows.Next() {
		var item publicSourceSummary
		var sourceIP string
		var bytes, observations int64
		if err := summaryRows.Scan(&sourceIP, &item.Mappings, &bytes, &observations, &item.LastSeenAt); err != nil {
			http.Error(w, "public source audit unavailable", http.StatusInternalServerError)
			return
		}
		if bytes > 0 {
			item.Bytes = uint64(bytes)
		}
		if observations > 0 {
			item.Observations = uint64(observations)
		}
		item.SourceIP = sourceIPForViewer(sourceIP, exact)
		item.SourceIPMasked = maskSourceIP(sourceIP)
		summary = append(summary, item)
	}
	if err := summaryRows.Err(); err != nil {
		http.Error(w, "public source audit unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, publicSourceAuditResponse{Records: records, Summary: summary, Total: total, RetentionDays: trafficRetentionDays, ExactSourceIP: exact})
}

// redactMetricsSourceIPs keeps the live connection endpoint useful for
// readonly operators without exposing raw public addresses by default.
func redactMetricsSourceIPs(metrics map[string]any, exact bool) map[string]any {
	if exact {
		return metrics
	}
	items, ok := metrics["connection_summary"].([]any)
	if !ok {
		return metrics
	}
	redacted := make([]any, 0, len(items))
	for _, item := range items {
		connection, ok := item.(map[string]any)
		if !ok {
			redacted = append(redacted, item)
			continue
		}
		copyOfConnection := make(map[string]any, len(connection))
		for key, value := range connection {
			copyOfConnection[key] = value
		}
		copyOfConnection["source_ip"] = maskSourceIP(jsonValueString(connection["source_ip"]))
		redacted = append(redacted, copyOfConnection)
	}
	copyOfMetrics := make(map[string]any, len(metrics))
	for key, value := range metrics {
		copyOfMetrics[key] = value
	}
	copyOfMetrics["connection_summary"] = redacted
	return copyOfMetrics
}

func redactTrafficRawJSON(raw string, exact bool) string {
	if exact || raw == "" {
		return raw
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var metrics map[string]any
	if decoder.Decode(&metrics) != nil {
		return raw
	}
	redacted, err := json.Marshal(redactMetricsSourceIPs(metrics, false))
	if err != nil {
		return raw
	}
	return string(redacted)
}
