package main

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// CoreMetrics 是本机 (Core 节点) 的实时系统指标, 由 core 进程直接采集,
// 不依赖 Edge 上报。前端节点页轮询 /api/metrics 获取。
type CoreMetrics struct {
	Time             time.Time `json:"time"`
	CPUPercent       float64   `json:"cpu_percent"`
	MemoryUsedBytes  uint64    `json:"memory_used_bytes"`
	MemoryTotalBytes uint64    `json:"memory_total_bytes"`
	DiskUsedBytes    uint64    `json:"disk_used_bytes"`
	DiskTotalBytes   uint64    `json:"disk_total_bytes"`
	Load1            float64   `json:"load_1"`
	Load5            float64   `json:"load_5"`
	Load15           float64   `json:"load_15"`
	Processes        int       `json:"processes"`
	UptimeSeconds    uint64    `json:"uptime_seconds"`
}

type coreCPUSample struct {
	At                time.Time
	CPUTotal, CPUIdle uint64
}

var coreCPU muSync
var previousCoreCPUSample coreCPUSample

// muSync 仅用于 core metrics 的 CPU 采样缓存 (命名避免与包内其它 mutex 混淆)。
type muSync struct{ sync.Mutex }

func collectCoreMetrics() CoreMetrics {
	now := time.Now()
	cpuTotal, cpuIdle := readCPUStat()
	memoryUsed, memoryTotal := readMemoryStat()
	diskUsed, diskTotal := readDiskStat()
	load1, load5, load15 := readLoadAvg()
	m := CoreMetrics{
		Time:             now,
		MemoryUsedBytes:  memoryUsed,
		MemoryTotalBytes: memoryTotal,
		DiskUsedBytes:    diskUsed,
		DiskTotalBytes:   diskTotal,
		Load1:            load1,
		Load5:            load5,
		Load15:           load15,
		Processes:        readProcessCount(),
		UptimeSeconds:    readUptime(),
	}
	coreCPU.Lock()
	previous := previousCoreCPUSample
	if !previous.At.IsZero() && cpuTotal > previous.CPUTotal {
		elapsed := now.Sub(previous.At).Seconds()
		if elapsed > 0 {
			totalDelta := cpuTotal - previous.CPUTotal
			idleDelta := cpuIdle - previous.CPUIdle
			m.CPUPercent = 100 * float64(totalDelta-idleDelta) / float64(totalDelta)
		}
	}
	previousCoreCPUSample = coreCPUSample{At: now, CPUTotal: cpuTotal, CPUIdle: cpuIdle}
	coreCPU.Unlock()
	if m.CPUPercent < 0 {
		m.CPUPercent = 0
	}
	if m.CPUPercent > 100 {
		m.CPUPercent = 100
	}
	return m
}

func coreMetricsHandler(w http.ResponseWriter, r *http.Request) {
	// Intentionally NOT audited: the dashboard polls this endpoint every few
	// seconds; writing an audit row per poll would flood the audit log with
	// ~17k rows/day per open page. Metrics are read-only system data.
	writeJSON(w, collectCoreMetrics())
}

func readCPUStat() (uint64, uint64) {
	body, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	line := strings.SplitN(string(body), "\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0
	}
	var total uint64
	values := make([]uint64, len(fields)-1)
	for index, value := range fields[1:] {
		values[index], _ = strconv.ParseUint(value, 10, 64)
		total += values[index]
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return total, idle
}

func readMemoryStat() (uint64, uint64) {
	body, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			values[strings.TrimSuffix(fields[0], ":")], _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}
	total := values["MemTotal"] * 1024
	available := values["MemAvailable"] * 1024
	if available > total {
		available = total
	}
	return total - available, total
}

func readDiskStat() (uint64, uint64) {
	var stat syscall.Statfs_t
	if syscall.Statfs("/", &stat) != nil {
		return 0, 0
	}
	total := stat.Blocks * uint64(stat.Bsize)
	available := stat.Bavail * uint64(stat.Bsize)
	return total - available, total
}

func readLoadAvg() (float64, float64, float64) {
	body, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(body))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	load1, _ := strconv.ParseFloat(fields[0], 64)
	load5, _ := strconv.ParseFloat(fields[1], 64)
	load15, _ := strconv.ParseFloat(fields[2], 64)
	return load1, load5, load15
}

func readProcessCount() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() && isNumericName(entry.Name()) {
			count++
		}
	}
	return count
}

func isNumericName(name string) bool {
	if name == "" {
		return false
	}
	for _, ch := range name {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func readUptime() uint64 {
	body, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(body))
	if len(fields) == 0 {
		return 0
	}
	value, _ := strconv.ParseFloat(fields[0], 64)
	return uint64(value)
}
