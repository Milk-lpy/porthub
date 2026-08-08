package main

import (
	"net"
	"porthub/internal/snapshots"
	"strconv"
	"strings"
	"time"
)

type connectionSummary struct {
	ObservedAt time.Time `json:"observed_at"`
	SourceIP   string    `json:"source_ip"`
	MappingID  string    `json:"mapping_id"`
	Mapping    string    `json:"mapping"`
	Protocol   string    `json:"protocol"`
	PublicPort int       `json:"public_port"`
	Target     string    `json:"target"`
	State      string    `json:"state"`
	Bytes      uint64    `json:"bytes"`
	Timeout    int       `json:"timeout_seconds"`
}

func collectConnectionSummary(mappings []snapshots.Mapping, limit int) []connectionSummary {
	if limit < 1 {
		return []connectionSummary{}
	}
	output, err := edgeNetdListConntrack()
	if err != nil {
		return []connectionSummary{}
	}
	result := make([]connectionSummary, 0, limit)
	for _, line := range strings.Split(string(output), "\n") {
		entry, ok := parseConntrackLine(line, mappings)
		if ok {
			result = append(result, entry)
			if len(result) == limit {
				break
			}
		}
	}
	return result
}

func parseConntrackLine(line string, mappings []snapshots.Mapping) (connectionSummary, bool) {
	fields := strings.Fields(line)
	// `conntrack -o extended` on current Ubuntu prefixes entries with the
	// address family (`ipv4 2 tcp ...` / `ipv6 10 udp ...`). Older conntrack
	// versions omit that prefix, so normalize both shapes before parsing.
	if len(fields) > 1 && (fields[0] == "ipv4" || fields[0] == "ipv6") {
		// The second field is the conntrack layer-3 protocol number.
		fields = fields[2:]
	}
	if len(fields) < 6 || (fields[0] != "tcp" && fields[0] != "udp") {
		return connectionSummary{}, false
	}
	protocol := fields[0]
	timeout, _ := strconv.Atoi(fields[2])
	values := map[string]string{}
	state := "active"
	for _, field := range fields[3:] {
		key, value, found := strings.Cut(field, "=")
		if !found {
			if field != "[ASSURED]" && field != "[UNREPLIED]" {
				state = strings.ToLower(strings.Trim(field, "[]"))
			}
			continue
		}
		if _, exists := values[key]; !exists {
			values[key] = value
		}
	}
	source := net.ParseIP(values["src"])
	port, err := strconv.Atoi(values["dport"])
	if source == nil || err != nil {
		return connectionSummary{}, false
	}
	mapping, ok := findConnectionMapping(mappings, protocol, port)
	if !ok {
		return connectionSummary{}, false
	}
	bytes, _ := strconv.ParseUint(values["bytes"], 10, 64)
	targetPort := mapping.TargetStart + port - mapping.PublicStart
	return connectionSummary{
		ObservedAt: time.Now().UTC(), SourceIP: source.String(), MappingID: mapping.ID, Mapping: mapping.Name,
		Protocol: protocol, PublicPort: port, Target: net.JoinHostPort(mapping.TargetIP, strconv.Itoa(targetPort)),
		State: state, Bytes: bytes, Timeout: timeout,
	}, true
}

func findConnectionMapping(mappings []snapshots.Mapping, protocol string, port int) (snapshots.Mapping, bool) {
	for _, mapping := range mappings {
		if !mapping.Enabled || port < mapping.PublicStart || port > mapping.PublicEnd {
			continue
		}
		if string(mapping.Protocol) == protocol || mapping.Protocol == snapshots.TCPUDP {
			return mapping, true
		}
	}
	return snapshots.Mapping{}, false
}
