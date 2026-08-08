package main

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"time"
)

type hostStatus struct {
	Host     string            `json:"host"`
	OS       string            `json:"os"`
	Arch     string            `json:"arch"`
	Time     time.Time         `json:"time"`
	Load     []float64         `json:"load"`
	Memory   map[string]uint64 `json:"memory_kb"`
	Disk     map[string]uint64 `json:"disk_root_bytes"`
	Networks []netCounter      `json:"networks"`
}

type netCounter struct {
	Name    string `json:"name"`
	RXBytes uint64 `json:"rx_bytes"`
	TXBytes uint64 `json:"tx_bytes"`
}

func status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, collectHostStatus())
}

func collectHostStatus() hostStatus {
	host, _ := os.Hostname()
	return hostStatus{
		Host:     host,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Time:     time.Now(),
		Load:     loadAvg(),
		Memory:   memInfo(),
		Disk:     diskRoot(),
		Networks: netDev(),
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}
