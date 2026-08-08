package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

type portUsageItem struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

func portUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	items := collectPortUsage()
	w.Header().Set("content-type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]any{"ports": items})
}

func collectPortUsage() []portUsageItem {
	seen := map[string]bool{}
	var items []portUsageItem
	for _, source := range []struct {
		path, protocol, state string
	}{
		{"/proc/net/tcp", "tcp", "0A"}, {"/proc/net/tcp6", "tcp", "0A"},
		{"/proc/net/udp", "udp", "07"}, {"/proc/net/udp6", "udp", "07"},
	} {
		file, err := os.Open(source.path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			port, state, ok := parseProcNetLine(scanner.Text())
			if !ok || state != source.state || port == 0 {
				continue
			}
			key := source.protocol + ":" + strconv.Itoa(port)
			if !seen[key] {
				seen[key] = true
				items = append(items, portUsageItem{Protocol: source.protocol, Port: port})
			}
		}
		file.Close()
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Protocol == items[j].Protocol {
			return items[i].Port < items[j].Port
		}
		return items[i].Protocol < items[j].Protocol
	})
	return items
}

func parseProcNetLine(line string) (int, string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 || !strings.Contains(fields[1], ":") {
		return 0, "", false
	}
	parts := strings.Split(fields[1], ":")
	port, err := strconv.ParseInt(parts[len(parts)-1], 16, 32)
	if err != nil {
		return 0, "", false
	}
	return int(port), fields[3], true
}
