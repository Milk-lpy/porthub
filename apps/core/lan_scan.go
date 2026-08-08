package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type lanScanRequest struct {
	Mode string `json:"mode"`
	Host string `json:"host"`
}

type lanScanPort struct {
	Port      int    `json:"port"`
	Service   string `json:"service"`
	Category  string `json:"category"`
	Risk      string `json:"risk"`
	Protocol  string `json:"protocol"`
	Suggested string `json:"suggested_name"`
}

type lanScanHost struct {
	IP             string        `json:"ip"`
	Reachable      bool          `json:"reachable"`
	Classification string        `json:"classification"`
	Ports          []lanScanPort `json:"ports"`
}

type lanScanState struct {
	Status     string        `json:"status"`
	Mode       string        `json:"mode"`
	StartedAt  string        `json:"started_at"`
	FinishedAt string        `json:"finished_at"`
	Progress   int           `json:"progress"`
	Total      int           `json:"total"`
	Hosts      []lanScanHost `json:"hosts"`
	Error      string        `json:"error,omitempty"`
}

var lanScanner = struct {
	sync.Mutex
	state  lanScanState
	cancel context.CancelFunc
}{state: lanScanState{Status: "idle", Hosts: []lanScanHost{}}}

var commonScanPorts = []int{22, 53, 80, 81, 88, 443, 445, 5000, 5001, 5432, 5900, 6379, 6443, 8006, 8080, 8081, 8088, 8096, 8098, 8443, 9000, 9090, 9091, 9443, 10000, 10888, 10889, 18080, 3000, 3010, 32400, 3389, 50000, 51820, 51821, 25565, 27015}

type scanPortProfile struct {
	service  string
	category string
	risk     string
	name     string
}

var scanPortProfiles = map[int]scanPortProfile{
	22: {"SSH", "远程管理", "高", "SSH 远程管理"}, 53: {"DNS", "基础设施", "中", "DNS 服务"}, 80: {"HTTP", "Web", "中", "Web 服务"}, 81: {"HTTP", "Web", "中", "Web 服务"}, 135: {"MSRPC", "Windows", "高", "Windows 系统服务"}, 139: {"NetBIOS", "Windows", "高", "Windows 文件服务"},
	443: {"HTTPS", "Web", "中", "HTTPS 服务"}, 445: {"SMB", "文件共享", "高", "SMB 文件共享"}, 5000: {"NAS Web", "NAS", "中", "NAS 管理"}, 5001: {"NAS HTTPS", "NAS", "中", "NAS 管理 HTTPS"},
	5432: {"PostgreSQL", "数据库", "高", "PostgreSQL 数据库"}, 5900: {"VNC", "远程管理", "高", "VNC 远程桌面"}, 6379: {"Redis", "数据库", "高", "Redis 数据库"}, 6443: {"Kubernetes", "基础设施", "高", "Kubernetes API"},
	8006: {"PVE Web", "虚拟化", "中", "PVE 管理"}, 8080: {"HTTP", "Web", "中", "Web 服务"}, 8081: {"HTTP", "Web", "中", "Web 服务"}, 8088: {"HTTP", "Web", "中", "Web 服务"}, 8096: {"Jellyfin", "媒体", "中", "Jellyfin 媒体"},
	8098: {"HTTP", "Web", "中", "Web 服务"}, 8443: {"HTTPS", "Web", "中", "HTTPS 服务"}, 9000: {"MinIO", "存储", "中", "MinIO 存储"}, 9090: {"Prometheus", "监控", "中", "Prometheus 监控"},
	9091: {"HTTP", "Web", "中", "Web 服务"}, 9443: {"PortHub", "网络管理", "中", "PortHub 管理"}, 10000: {"Webmin", "远程管理", "高", "Webmin 管理"}, 10888: {"SOCKS5", "代理", "中", "SOCKS5 代理"}, 10889: {"Config HTTP", "配置分发", "中", "配置分发"},
	18080: {"HTTP", "Web", "中", "HTTP 服务"}, 3000: {"HTTP", "Web", "中", "Web 服务"}, 3010: {"HTTP", "Web", "中", "Web 服务"}, 32400: {"Plex", "媒体", "中", "Plex 媒体"},
	3389: {"RDP", "远程管理", "高", "Windows 远程桌面"}, 50000: {"Jenkins", "开发工具", "高", "Jenkins"}, 51820: {"WireGuard", "网络基础设施", "中", "WireGuard"}, 51821: {"WireGuard", "网络基础设施", "中", "WireGuard"}, 25565: {"Minecraft", "游戏", "中", "Minecraft 游戏"}, 27015: {"Steam 游戏", "游戏", "中", "Steam 游戏"},
}

func lanScan(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		lanScanner.Lock()
		state := lanScanner.state
		lanScanner.Unlock()
		if state.Status == "idle" {
			state = loadLatestLanScan(state)
		}
		writeJSON(w, state)
	case http.MethodDelete:
		lanScanner.Lock()
		if lanScanner.state.Status != "running" || lanScanner.cancel == nil {
			lanScanner.Unlock()
			http.Error(w, "当前没有正在运行的扫描", http.StatusConflict)
			return
		}
		lanScanner.cancel()
		lanScanner.Unlock()
		audit(actor(r), "lan_scan_stop", "manual stop requested")
		writeJSON(w, map[string]any{"ok": true, "status": "stopping"})
	case http.MethodPost:
		var request lanScanRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "扫描参数无效", http.StatusBadRequest)
			return
		}
		mode, hosts, ports, err := prepareLanScan(request)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		lanScanner.Lock()
		if lanScanner.state.Status == "running" {
			lanScanner.Unlock()
			http.Error(w, "已有扫描任务正在运行", http.StatusConflict)
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		lanScanner.state = lanScanState{Status: "running", Mode: mode, StartedAt: time.Now().UTC().Format(time.RFC3339), Hosts: []lanScanHost{}, Total: len(hosts) * len(ports)}
		lanScanner.cancel = cancel
		persistLanScan(lanScanner.state)
		lanScanner.Unlock()
		audit(actor(r), "lan_scan_start", fmt.Sprintf("mode=%s hosts=%d ports=%d", mode, len(hosts), len(ports)))
		go runLanScan(ctx, mode, hosts, ports)
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "status": "running"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func prepareLanScan(request lanScanRequest) (string, []string, []int, error) {
	mode := strings.ToLower(strings.TrimSpace(request.Mode))
	if mode == "" {
		mode = "common"
	}
	if mode != "common" && mode != "deep" {
		return "", nil, nil, fmt.Errorf("扫描模式只能是 common 或 deep")
	}
	hosts, err := scanHosts(request.Host)
	if err != nil {
		return "", nil, nil, err
	}
	ports := commonScanPorts
	if mode == "deep" {
		ports = make([]int, 65535)
		for index := range ports {
			ports[index] = index + 1
		}
	}
	if len(hosts)*len(ports) > 20000000 {
		return "", nil, nil, fmt.Errorf("深度扫描范围超过 2000 万次探测，请缩小 PortHub 配置的局域网网段")
	}
	return mode, hosts, ports, nil
}

func scanHosts(raw string) ([]string, error) {
	if strings.TrimSpace(raw) != "" {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || !managedLANIP(ip) {
			return nil, fmt.Errorf("IP 不在 PortHub 配置的局域网范围内")
		}
		return []string{ip.String()}, nil
	}
	var hosts []string
	for _, network := range coreForwardConfig.LANCIDRs {
		for ip := network.IP.Mask(network.Mask); network.Contains(ip); incrementIP(ip) {
			if !isNetworkOrBroadcast(ip, network) {
				hosts = append(hosts, ip.String())
			}
			if len(hosts) > 256 {
				return nil, fmt.Errorf("局域网范围超过 256 台，不能执行全局深度扫描")
			}
		}
	}
	return hosts, nil
}

func managedLANIP(ip net.IP) bool {
	for _, network := range coreForwardConfig.LANCIDRs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func isNetworkOrBroadcast(ip net.IP, network *net.IPNet) bool {
	if ip.Equal(network.IP.Mask(network.Mask)) {
		return true
	}
	broadcast := make(net.IP, len(network.IP))
	for index := range network.IP {
		broadcast[index] = network.IP[index] | ^network.Mask[index]
	}
	return ip.Equal(broadcast)
}

func incrementIP(ip net.IP) {
	for index := len(ip) - 1; index >= 0; index-- {
		ip[index]++
		if ip[index] != 0 {
			break
		}
	}
}

func runLanScan(ctx context.Context, mode string, hosts []string, ports []int) {
	previous := loadLatestLanScan(lanScanState{Status: "idle", Hosts: []lanScanHost{}})
	results := make(map[string][]lanScanPort)
	var lock sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan struct {
		host string
		port int
	}, 256)
	progress := 0
	lastPersist := 0
	worker := func() {
		defer wg.Done()
		for job := range jobs {
			host, port := job.host, job.port
			dialCtx, cancel := context.WithTimeout(ctx, 220*time.Millisecond)
			dialer := net.Dialer{}
			connection, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
			cancel()
			if err == nil {
				connection.Close()
				profile := scanPortProfiles[port]
				if profile.service == "" {
					profile = scanPortProfile{"TCP", "未分类", "低", fmt.Sprintf("TCP %d", port)}
				}
				lock.Lock()
				results[host] = append(results[host], lanScanPort{Port: port, Service: profile.service, Category: profile.category, Risk: profile.risk, Protocol: "tcp", Suggested: profile.name})
				lock.Unlock()
			}
			lock.Lock()
			progress++
			current := progress
			lock.Unlock()
			lanScanner.Lock()
			lanScanner.state.Progress = current
			shouldPersist := current-lastPersist >= 512
			if shouldPersist {
				lastPersist = current
				lanScanner.state.Hosts = snapshotScanResults(results, &lock)
			}
			lanScanner.Unlock()
			if shouldPersist {
				persistLanScan(currentScanState())
			}
		}
	}
	for i := 0; i < 256; i++ {
		wg.Add(1)
		go worker()
	}
feedLoop:
	for _, host := range hosts {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				break feedLoop
			case jobs <- struct {
				host string
				port int
			}{host, port}:
			}
		}
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		now := time.Now().UTC().Format(time.RFC3339)
		lanScanner.Lock()
		lanScanner.state.Status = "stopped"
		lanScanner.state.FinishedAt = now
		lanScanner.state.Hosts = snapshotScanResults(results, &lock)
		lanScanner.state.Error = "扫描已停止，已保留停止前发现的数据"
		finalState := lanScanner.state
		lanScanner.cancel = nil
		lanScanner.Unlock()
		persistLanScan(finalState)
		audit("system", "lan_scan_stopped", fmt.Sprintf("mode=%s progress=%d/%d", mode, finalState.Progress, finalState.Total))
		return
	}
	output := make([]lanScanHost, 0, len(results))
	for host, portsForHost := range results {
		sort.Slice(portsForHost, func(i, j int) bool { return portsForHost[i].Port < portsForHost[j].Port })
		output = append(output, lanScanHost{IP: host, Reachable: true, Classification: classifyHost(portsForHost), Ports: portsForHost})
	}
	sort.Slice(output, func(i, j int) bool { return output[i].IP < output[j].IP })
	now := time.Now().UTC().Format(time.RFC3339)
	lanScanner.Lock()
	lanScanner.state.Status = "completed"
	lanScanner.state.FinishedAt = now
	lanScanner.state.Hosts = output
	lanScanner.state.Progress = lanScanner.state.Total
	finalState := lanScanner.state
	lanScanner.cancel = nil
	lanScanner.Unlock()
	persistLanScan(finalState)
	reconcileLanScanAlerts(previous, finalState)
	audit("system", "lan_scan_complete", fmt.Sprintf("mode=%s hosts=%d open_hosts=%d", mode, len(hosts), len(output)))
}

func currentScanState() lanScanState {
	lanScanner.Lock()
	defer lanScanner.Unlock()
	return lanScanner.state
}

func snapshotScanResults(results map[string][]lanScanPort, lock sync.Locker) []lanScanHost {
	lock.Lock()
	defer lock.Unlock()
	output := make([]lanScanHost, 0, len(results))
	for host, ports := range results {
		copyPorts := append([]lanScanPort(nil), ports...)
		sort.Slice(copyPorts, func(i, j int) bool { return copyPorts[i].Port < copyPorts[j].Port })
		output = append(output, lanScanHost{IP: host, Reachable: true, Classification: classifyHost(copyPorts), Ports: copyPorts})
	}
	sort.Slice(output, func(i, j int) bool { return output[i].IP < output[j].IP })
	return output
}

func lanScanScheduler(interval time.Duration) {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		lanScanner.Lock()
		running := lanScanner.state.Status == "running"
		lanScanner.Unlock()
		if running {
			continue
		}
		mode, hosts, ports, err := prepareLanScan(lanScanRequest{Mode: "common"})
		if err != nil {
			setControlAlert("lan-scan:config", "warning", "局域网扫描未执行", err.Error(), true)
			continue
		}
		lanScanner.Lock()
		lanScanner.state = lanScanState{Status: "running", Mode: mode, StartedAt: time.Now().UTC().Format(time.RFC3339), Hosts: []lanScanHost{}, Total: len(hosts) * len(ports)}
		lanScanner.Unlock()
		go func() {
			scanCtx, scanCancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer scanCancel()
			runLanScan(scanCtx, mode, hosts, ports)
		}()
	}
}

func reconcileLanScanAlerts(previous, current lanScanState) {
	if db == nil {
		return
	}
	oldPorts := map[string]bool{}
	for _, host := range previous.Hosts {
		for _, port := range host.Ports {
			oldPorts[fmt.Sprintf("%s:%d/%s", host.IP, port.Port, port.Protocol)] = true
		}
	}
	newPorts := map[string]bool{}
	for _, host := range current.Hosts {
		for _, port := range host.Ports {
			fingerprint := fmt.Sprintf("lan-scan:%s:%d:%s", host.IP, port.Port, port.Protocol)
			key := fmt.Sprintf("%s:%d/%s", host.IP, port.Port, port.Protocol)
			newPorts[key] = true
			if !oldPorts[key] {
				setControlAlert(fingerprint, "warning", "发现新的局域网端口", fmt.Sprintf("%s %s:%d，分类为%s", port.Service, host.IP, port.Port, port.Category), true)
			}
		}
	}
	rows, err := db.Query("select fingerprint from system_alerts where source='control' and fingerprint like 'lan-scan:%' and active=1")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var fingerprint string
		if rows.Scan(&fingerprint) != nil {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(fingerprint, "lan-scan:"), ":")
		if len(parts) >= 3 {
			key := fmt.Sprintf("%s:%s/%s", strings.Join(parts[:len(parts)-2], ":"), parts[len(parts)-2], parts[len(parts)-1])
			if !newPorts[key] {
				setControlAlert(fingerprint, "warning", "局域网端口已关闭", "上一次扫描发现的端口已不再接受 TCP 连接", false)
			}
		}
	}
}

func persistLanScan(state lanScanState) {
	if db == nil {
		return
	}
	result, err := json.Marshal(state.Hosts)
	if err != nil {
		return
	}
	_, _ = db.Exec("insert into lan_scan_runs(mode,started_at,finished_at,status,progress,total,result_json,error) values(?,?,?,?,?,?,?,?)", state.Mode, state.StartedAt, state.FinishedAt, state.Status, state.Progress, state.Total, string(result), state.Error)
	_, _ = db.Exec("delete from lan_scan_runs where id not in (select id from lan_scan_runs order by id desc limit 5)")
}

// resumeLanScan makes an interrupted scan independent from the browser and
// restarts it after a Core restart. The scan is intentionally restarted from
// the beginning so the persisted result is never a partial, misleading catalog.
func resumeLanScan() {
	if db == nil {
		return
	}
	var mode, status string
	if err := db.QueryRow("select mode,status from lan_scan_runs order by id desc limit 1").Scan(&mode, &status); err != nil || status != "running" {
		return
	}
	mode, hosts, ports, err := prepareLanScan(lanScanRequest{Mode: mode})
	if err != nil {
		_, _ = db.Exec("update lan_scan_runs set status='failed',finished_at=?,error=? where id=(select id from lan_scan_runs order by id desc limit 1)", time.Now().UTC().Format(time.RFC3339), err.Error())
		return
	}
	lanScanner.Lock()
	lanScanner.state = lanScanState{Status: "running", Mode: mode, StartedAt: time.Now().UTC().Format(time.RFC3339), Hosts: []lanScanHost{}, Total: len(hosts) * len(ports)}
	lanScanner.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	lanScanner.Lock()
	lanScanner.cancel = cancel
	lanScanner.Unlock()
	go runLanScan(ctx, mode, hosts, ports)
}

func loadLatestLanScan(fallback lanScanState) lanScanState {
	if db == nil {
		return fallback
	}
	var state lanScanState
	var hostsJSON string
	if err := db.QueryRow("select mode,started_at,finished_at,status,progress,total,result_json,error from lan_scan_runs order by id desc limit 1").Scan(&state.Mode, &state.StartedAt, &state.FinishedAt, &state.Status, &state.Progress, &state.Total, &hostsJSON, &state.Error); err != nil {
		return fallback
	}
	if json.Unmarshal([]byte(hostsJSON), &state.Hosts) != nil {
		state.Hosts = []lanScanHost{}
	}
	return state
}

func classifyHost(ports []lanScanPort) string {
	seen := map[string]bool{}
	for _, port := range ports {
		seen[port.Category] = true
	}
	for _, category := range []string{"虚拟化", "NAS", "Windows", "存储", "数据库", "游戏", "Web", "远程管理", "基础设施"} {
		if seen[category] {
			return category
		}
	}
	return "Linux / 未分类"
}
