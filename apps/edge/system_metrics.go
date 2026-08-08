package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type metricAlert struct {
	Fingerprint string `json:"fingerprint"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Detail      string `json:"detail"`
}

type edgeSystemMetrics struct {
	PublicInterface                    string
	RXBytes, TXBytes                   uint64
	RXBytesPerSecond, TXBytesPerSecond uint64
	CPUPercent, Load1                  float64
	MemoryUsedBytes, MemoryTotalBytes  uint64
	DiskUsedBytes, DiskTotalBytes      uint64
	Connections, ConntrackMax          int
	Alerts                             []metricAlert
}

type edgeMetricSample struct {
	At                time.Time
	Interface         string
	RXBytes, TXBytes  uint64
	CPUTotal, CPUIdle uint64
}

var edgeMetricSampleMu sync.Mutex
var previousEdgeMetricSample edgeMetricSample

func collectEdgeSystemMetrics() edgeSystemMetrics {
	now := time.Now()
	metric := edgeSystemMetrics{PublicInterface: defaultRouteInterface()}
	metric.RXBytes = readUintFile(filepath.Join("/sys/class/net", metric.PublicInterface, "statistics/rx_bytes"))
	metric.TXBytes = readUintFile(filepath.Join("/sys/class/net", metric.PublicInterface, "statistics/tx_bytes"))
	cpuTotal, cpuIdle := readCPUStat()
	metric.MemoryUsedBytes, metric.MemoryTotalBytes = readMemoryStat()
	metric.DiskUsedBytes, metric.DiskTotalBytes = readDiskStat()
	metric.Load1 = readLoad1()
	metric.Connections = int(readUintFile("/proc/sys/net/netfilter/nf_conntrack_count"))
	metric.ConntrackMax = int(readUintFile("/proc/sys/net/netfilter/nf_conntrack_max"))

	edgeMetricSampleMu.Lock()
	previous := previousEdgeMetricSample
	if !previous.At.IsZero() && previous.Interface == metric.PublicInterface {
		elapsed := now.Sub(previous.At).Seconds()
		if elapsed > 0 {
			metric.RXBytesPerSecond = counterRate(previous.RXBytes, metric.RXBytes, elapsed)
			metric.TXBytesPerSecond = counterRate(previous.TXBytes, metric.TXBytes, elapsed)
		}
		if cpuTotal > previous.CPUTotal {
			totalDelta := cpuTotal - previous.CPUTotal
			idleDelta := cpuIdle - previous.CPUIdle
			metric.CPUPercent = 100 * float64(totalDelta-idleDelta) / float64(totalDelta)
		}
	}
	previousEdgeMetricSample = edgeMetricSample{At: now, Interface: metric.PublicInterface, RXBytes: metric.RXBytes, TXBytes: metric.TXBytes, CPUTotal: cpuTotal, CPUIdle: cpuIdle}
	edgeMetricSampleMu.Unlock()
	metric.Alerts = buildMetricAlerts(metric)
	return metric
}

func defaultRouteInterface() string {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[1] == "00000000" && fields[3] != "0000" && filepath.Base(fields[0]) == fields[0] {
			return fields[0]
		}
	}
	return ""
}

func readCPUStat() (uint64, uint64) {
	body, _ := os.ReadFile("/proc/stat")
	line := strings.SplitN(string(body), "\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0
	}
	values := make([]uint64, len(fields)-1)
	var total uint64
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
	body, _ := os.ReadFile("/proc/meminfo")
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

func readLoad1() float64 {
	body, _ := os.ReadFile("/proc/loadavg")
	fields := strings.Fields(string(body))
	if len(fields) == 0 {
		return 0
	}
	value, _ := strconv.ParseFloat(fields[0], 64)
	return value
}

func readUintFile(path string) uint64 {
	body, _ := os.ReadFile(path)
	value, _ := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	return value
}

func counterRate(previous, current uint64, seconds float64) uint64 {
	if current < previous || seconds <= 0 {
		return 0
	}
	return uint64(float64(current-previous) / seconds)
}

func buildMetricAlerts(metric edgeSystemMetrics) []metricAlert {
	alerts := []metricAlert{}
	if metric.ConntrackMax > 0 && metric.Connections*100/metric.ConntrackMax >= 80 {
		alerts = append(alerts, metricAlert{Fingerprint: "edge:conntrack", Severity: thresholdSeverity(metric.Connections, metric.ConntrackMax), Title: "连接跟踪容量偏高", Detail: fmt.Sprintf("当前 %d / %d", metric.Connections, metric.ConntrackMax)})
	}
	if metric.MemoryTotalBytes > 0 && metric.MemoryUsedBytes*100/metric.MemoryTotalBytes >= 85 {
		alerts = append(alerts, metricAlert{Fingerprint: "edge:memory", Severity: thresholdSeverity64(metric.MemoryUsedBytes, metric.MemoryTotalBytes), Title: "Edge 内存使用率偏高", Detail: "建议检查异常连接或代理负载"})
	}
	if metric.DiskTotalBytes > 0 && metric.DiskUsedBytes*100/metric.DiskTotalBytes >= 85 {
		alerts = append(alerts, metricAlert{Fingerprint: "edge:disk", Severity: thresholdSeverity64(metric.DiskUsedBytes, metric.DiskTotalBytes), Title: "Edge 磁盘空间不足", Detail: "建议清理非 PortHub 日志或扩容"})
	}
	return alerts
}

func thresholdSeverity(value, total int) string {
	if total > 0 && value*100/total >= 95 {
		return "critical"
	}
	return "warning"
}

func thresholdSeverity64(value, total uint64) string {
	if total > 0 && value*100/total >= 95 {
		return "critical"
	}
	return "warning"
}
