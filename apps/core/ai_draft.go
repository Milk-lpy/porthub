package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"porthub/internal/snapshots"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type aiDraftRequest struct {
	Intent string `json:"intent"`
}

type aiDraftResult struct {
	OK                   bool                `json:"ok"`
	Engine               string              `json:"engine"`
	GroupName            string              `json:"group_name"`
	Mappings             []snapshots.Mapping `json:"mappings"`
	Warnings             []string            `json:"warnings"`
	Blockers             []string            `json:"blockers"`
	RequiresConfirmation bool                `json:"requires_confirmation"`
}

type intentDraftEngine interface {
	Draft(string) (aiDraftResult, error)
}

type localRuleDraftEngine struct{}

var ipv4IntentPattern = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)
var numberIntentPattern = regexp.MustCompile(`[0-9]{1,5}`)

func aiDraft(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]any{"engine": "local_rule_parser", "external_upload": false, "execution": false, "max_intent_bytes": 2000})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var request aiDraftRequest
	if json.NewDecoder(r.Body).Decode(&request) != nil {
		http.Error(w, "invalid draft request", http.StatusBadRequest)
		return
	}
	result, err := (localRuleDraftEngine{}).Draft(request.Intent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(actor(r), "ai_draft_generate", strconv.Itoa(len(result.Mappings))+" mappings")
	writeJSON(w, result)
}

func (localRuleDraftEngine) Draft(intent string) (aiDraftResult, error) {
	intent = strings.TrimSpace(intent)
	if len(intent) < 3 || len(intent) > 2000 {
		return aiDraftResult{}, errors.New("intent must be 3-2000 characters")
	}
	result := aiDraftResult{OK: true, Engine: "local_rule_parser", GroupName: draftGroupName(intent), RequiresConfirmation: true}
	targetIP := firstValidIntentIP(intent)
	if targetIP == "" {
		result.Blockers = append(result.Blockers, "没有识别到目标 IP，请补充内网设备地址")
	}
	ports := intentPorts(intent)
	if len(ports) == 0 {
		ports = templateIntentPorts(intent)
	}
	if len(ports) == 0 {
		result.Blockers = append(result.Blockers, "没有识别到端口，请填写 1-65535 的服务端口")
	}
	if len(ports) > 64 {
		return result, errors.New("one AI draft may contain at most 64 ports")
	}
	protocol := draftProtocol(intent)
	for _, port := range ports {
		mapping := snapshots.Mapping{
			Name: result.GroupName + " " + strconv.Itoa(port), TargetIP: targetIP,
			PublicStart: port, PublicEnd: port, TargetStart: port, TargetEnd: port,
			Protocol: protocol, Enabled: false, LogLevel: "info", SourceMode: "compat",
			Description: "由本地 AI 助手生成的待确认草稿",
		}
		if targetIP != "" {
			check := mapping
			check.Enabled = true
			if err := snapshots.ValidateMappings([]snapshots.Mapping{check}); err != nil {
				return result, err
			}
		}
		result.Mappings = append(result.Mappings, mapping)
	}
	result.Warnings = append(result.Warnings, draftRiskWarnings(intent, ports)...)
	if len(result.Warnings) == 0 {
		result.Warnings = append(result.Warnings, "草稿默认禁用；保存后仍需在映射页检查并手工部署")
	}
	return result, nil
}

func firstValidIntentIP(intent string) string {
	for _, value := range ipv4IntentPattern.FindAllString(intent, -1) {
		if ip := net.ParseIP(value); ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

func intentPorts(intent string) []int {
	withoutIPs := ipv4IntentPattern.ReplaceAllString(intent, " ")
	seen := map[int]bool{}
	ports := []int{}
	for _, value := range numberIntentPattern.FindAllString(withoutIPs, -1) {
		port, _ := strconv.Atoi(value)
		if port >= 1 && port <= 65535 && !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	return ports
}

func templateIntentPorts(intent string) []int {
	lower := strings.ToLower(intent)
	switch {
	case strings.Contains(intent, "饥荒") || strings.Contains(lower, "don't starve"):
		return []int{11001, 11002}
	case strings.Contains(lower, "minecraft") || strings.Contains(intent, "我的世界"):
		return []int{25565}
	case strings.Contains(lower, "palworld") || strings.Contains(intent, "幻兽帕鲁"):
		return []int{8211}
	case strings.Contains(intent, "远程桌面") || strings.Contains(lower, "rdp"):
		return []int{3389}
	case strings.Contains(lower, "ssh"):
		return []int{22}
	}
	return nil
}

func draftProtocol(intent string) snapshots.Protocol {
	upper := strings.ToUpper(intent)
	if (strings.Contains(upper, "TCP") && strings.Contains(upper, "UDP")) || strings.Contains(upper, "TCP+UDP") {
		return snapshots.TCPUDP
	}
	if strings.Contains(upper, "UDP") || strings.Contains(intent, "饥荒") || strings.Contains(strings.ToLower(intent), "palworld") {
		return snapshots.UDP
	}
	return snapshots.TCP
}

func draftGroupName(intent string) string {
	for _, candidate := range []string{"饥荒", "Minecraft", "Palworld", "NAS", "SSH", "RDP", "Web"} {
		if strings.Contains(strings.ToLower(intent), strings.ToLower(candidate)) {
			return candidate
		}
	}
	return "AI 发布草稿"
}

func draftRiskWarnings(intent string, ports []int) []string {
	highRisk := map[int]string{22: "SSH", 3389: "RDP", 445: "SMB", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis"}
	warnings := []string{}
	for _, port := range ports {
		if service := highRisk[port]; service != "" {
			warnings = append(warnings, service+" 不建议直接暴露公网，请优先使用 WireGuard 或配置 IP 白名单")
		}
	}
	if strings.Contains(intent, "保留源 IP") {
		warnings = append(warnings, "保留源 IP 需要额外回程路由，草稿不会自动启用该模式")
	}
	return warnings
}
