//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

func loadAvg() []float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(b))
	out := make([]float64, 0, 3)
	for i := 0; i < 3 && i < len(fields); i++ {
		v, _ := strconv.ParseFloat(fields[i], 64)
		out = append(out, v)
	}
	return out
}

func memInfo() map[string]uint64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	out := map[string]uint64{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		if key != "MemTotal" && key != "MemAvailable" && key != "SwapTotal" && key != "SwapFree" {
			continue
		}
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		out[key] = v
	}
	return out
}

func diskRoot() map[string]uint64 {
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) != nil {
		return nil
	}
	return map[string]uint64{
		"total": st.Blocks * uint64(st.Bsize),
		"free":  st.Bavail * uint64(st.Bsize),
	}
}

func netDev() []netCounter {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil
	}
	var out []netCounter
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		out = append(out, netCounter{Name: name, RXBytes: rx, TXBytes: tx})
	}
	return out
}
