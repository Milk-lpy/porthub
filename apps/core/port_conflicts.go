package main

import (
	"encoding/json"
	"fmt"
	"porthub/internal/snapshots"
	"strconv"
)

func checkEdgePortAvailability(mappings []snapshots.Mapping) ([]string, error) {
	response, err := getEdgeJSON("/api/port-usage")
	if err != nil {
		return nil, err
	}
	occupied := map[string]bool{}
	if raw, ok := response["ports"].([]any); ok {
		for _, value := range raw {
			item, ok := value.(map[string]any)
			if !ok {
				continue
			}
			protocol, _ := item["protocol"].(string)
			var port int
			switch number := item["port"].(type) {
			case json.Number:
				port, _ = strconv.Atoi(number.String())
			case float64:
				port = int(number)
			}
			occupied[fmt.Sprintf("%s:%d", protocol, port)] = true
		}
	}
	return findEdgePortConflicts(mappings, occupied), nil
}

func findEdgePortConflicts(mappings []snapshots.Mapping, occupied map[string]bool) []string {
	var conflicts []string
	for _, mapping := range mappings {
		if !mapping.Enabled {
			continue
		}
		protocols := []snapshots.Protocol{mapping.Protocol}
		if mapping.Protocol == snapshots.TCPUDP {
			protocols = []snapshots.Protocol{snapshots.TCP, snapshots.UDP}
		}
		for _, protocol := range protocols {
			for port := mapping.PublicStart; port <= mapping.PublicEnd; port++ {
				if occupied[fmt.Sprintf("%s:%d", protocol, port)] {
					conflicts = append(conflicts, fmt.Sprintf("%s/%d is already listened on Edge", protocol, port))
				}
			}
		}
	}
	return conflicts
}
