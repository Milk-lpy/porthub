package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// auditRecord is a presentation model. The original four audit columns stay
// intact so existing integrations continue to work, while the API exposes
// enough context for a human-readable audit timeline.
type auditRecord struct {
	ID            int64  `json:"id"`
	TS            string `json:"ts"`
	Actor         string `json:"actor"`
	Action        string `json:"action"`
	Detail        string `json:"detail"`
	ActionLabel   string `json:"action_label"`
	Category      string `json:"category"`
	CategoryLabel string `json:"category_label"`
	Severity      string `json:"severity"`
	SeverityLabel string `json:"severity_label"`
	Result        string `json:"result"`
	ResultLabel   string `json:"result_label"`
	Target        string `json:"target"`
	Summary       string `json:"summary"`
	System        bool   `json:"system"`
}

type auditActionMeta struct {
	label    string
	category string
	severity string
	result   string
}

var auditActionLabels = map[string]string{
	"login":                        "登录成功",
	"login_failed":                 "登录失败",
	"login_rate_limited":           "登录受限",
	"password_change":              "修改密码",
	"mapping_create":               "新增映射",
	"mapping_update":               "修改映射",
	"mapping_delete":               "删除映射",
	"mapping_import":               "导入映射",
	"mapping_bulk_enable":          "批量启用映射",
	"mapping_bulk_disable":         "批量停用映射",
	"mapping_bulk_delete":          "批量删除映射",
	"port_forward_create":          "新增端口转发",
	"port_forward_update":          "修改端口转发",
	"port_forward_delete":          "删除端口转发",
	"port_forward_toggle":          "切换端口转发",
	"port_forward_batch_toggle":    "批量切换端口转发",
	"port_forward_duplicate":       "复制端口转发",
	"port_forward_apply":           "应用端口转发",
	"snapshot_generate":            "生成配置快照",
	"snapshot_rollback":            "回滚配置快照",
	"deploy_success":               "配置下发成功",
	"deploy_failed":                "配置下发失败",
	"core_forward_deploy_failed":   "Core 转发下发失败",
	"wireguard_peer_create":        "新增 WireGuard 节点",
	"wireguard_peer_update":        "修改 WireGuard 节点",
	"wireguard_peer_delete":        "删除 WireGuard 节点",
	"wireguard_peer_deploy":        "下发 WireGuard 节点",
	"wireguard_peer_deploy_failed": "WireGuard 节点下发失败",
	"domain_create":                "新增域名",
	"domain_update":                "修改域名",
	"domain_delete":                "删除域名",
	"ddns_provider_create":         "新增 DDNS 服务商",
	"ddns_provider_update":         "修改 DDNS 服务商",
	"ddns_provider_delete":         "删除 DDNS 服务商",
	"ddns_record_create":           "新增 DDNS 记录",
	"ddns_record_update":           "修改 DDNS 记录",
	"ddns_record_delete":           "删除 DDNS 记录",
	"ddns_sync":                    "同步 DDNS",
	"ddns_scheduled_sync":          "定时同步 DDNS",
	"ddns_sync_alert":              "DDNS 同步告警",
	"certificate_create":           "新增证书",
	"certificate_update":           "修改证书",
	"certificate_delete":           "删除证书",
	"certificate_import":           "导入证书",
	"certificate_deploy":           "部署证书",
	"certificate_plan":             "预检查证书",
	"certificate_acme_prepare":     "准备 ACME 证书",
	"certificate_acme_issued":      "签发 ACME 证书",
	"certificate_acme_failed":      "签发 ACME 证书失败",
	"acl_rule_create":              "新增 ACL 规则",
	"acl_rule_update":              "修改 ACL 规则",
	"acl_rule_delete":              "删除 ACL 规则",
	"ip_set_create":                "新增 IP 集合",
	"ip_set_update":                "修改 IP 集合",
	"ip_set_delete":                "删除 IP 集合",
	"ip_set_import":                "导入 IP 集合",
	"ip_feed_create":               "新增 IP 数据源",
	"ip_feed_update":               "修改 IP 数据源",
	"ip_feed_delete":               "删除 IP 数据源",
	"ip_feed_sync":                 "同步 IP 数据源",
	"agent_enrollment_create":      "创建 Agent 注册邀请",
	"agent_registered":             "Agent 注册",
	"lan_scan_start":               "开始局域网扫描",
	"lan_scan_stop":                "停止局域网扫描",
	"lan_scan_stopped":             "局域网扫描已停止",
	"lan_scan_complete":            "局域网扫描完成",
	"resource_create":              "新增资源",
	"resource_update":              "修改资源",
	"resource_delete":              "删除资源",
	"service_create":               "新增服务",
	"service_update":               "修改服务",
	"service_delete":               "删除服务",
	"mapping_group_create":         "新增映射组",
	"mapping_group_update":         "修改映射组",
	"mapping_group_delete":         "删除映射组",
	"http_proxy_create":            "新增反向代理",
	"http_proxy_update":            "修改反向代理",
	"http_proxy_delete":            "删除反向代理",
	"api_token_create":             "创建 API Token",
	"api_token_revoke":             "撤销 API Token",
	"user_create":                  "新增用户",
	"user_update":                  "修改用户",
	"user_delete":                  "删除用户",
	"user_password_reset":          "重置用户密码",
	"user_totp_reset":              "重置用户二次验证",
	"backup_create":                "创建备份",
	"backup_restore_plan":          "生成恢复计划",
	"backup_restore_plan_failed":   "生成恢复计划失败",
	"backup_download":              "下载备份",
	"update_check":                 "检查更新",
	"update_stage":                 "准备更新",
	"alert_acknowledge":            "确认告警",
	"edge_metrics_read":            "查看 Edge 指标",
	"traffic_sample_collect":       "采集流量样本",
	"ai_draft_generate":            "生成助手草稿",
	"template_apply":               "应用服务模板",
	"webhook_create":               "新增 Webhook",
	"webhook_update":               "修改 Webhook",
	"webhook_delete":               "删除 Webhook",
	"managed_service_start":        "启动托管服务",
	"managed_service_stop":         "停止托管服务",
	"managed_service_restart":      "重启托管服务",
	"managed_service_enable":       "启用开机启动",
	"managed_service_disable":      "停用开机启动",
	"mapping_groups_create":        "新增映射组",
	"mapping_groups_update":        "修改映射组",
	"mapping_groups_delete":        "删除映射组",
	"acls_create":                  "新增 ACL 定义",
	"acls_update":                  "修改 ACL 定义",
	"acls_delete":                  "删除 ACL 定义",
	"templates_create":             "新增发布模板",
	"templates_update":             "修改发布模板",
	"templates_delete":             "删除发布模板",
	"webhooks_create":              "新增 Webhook",
	"webhooks_update":              "修改 Webhook",
	"webhooks_delete":              "删除 Webhook",
	"backup_scheduled":             "定时创建备份",
	"backup_scheduled_failed":      "定时备份失败",
}

var auditCategoryLabels = map[string]string{
	"auth":      "身份与权限",
	"mapping":   "映射与入口",
	"proxy":     "反向代理",
	"config":    "配置下发",
	"network":   "节点与网络",
	"domain":    "域名与证书",
	"security":  "安全策略",
	"inventory": "资源发现",
	"traffic":   "流量监控",
	"backup":    "备份恢复",
	"system":    "系统管理",
	"assistant": "命令助手",
	"service":   "服务管理",
	"other":     "其他操作",
}

func auditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	records, err := queryAuditRecords(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, records)
}

func queryAuditRecords(r *http.Request) ([]auditRecord, error) {
	limit := boundedLimit(r, 200)
	if limit > 500 {
		limit = 500
	}
	queryValues := r.URL.Query()
	where := []string{"1=1"}
	args := make([]any, 0, 4)
	if action := strings.TrimSpace(queryValues.Get("action")); action != "" && len(action) <= 96 {
		where = append(where, "action = ?")
		args = append(args, action)
	}
	if actor := strings.TrimSpace(queryValues.Get("actor")); actor != "" && len(actor) <= 128 {
		where = append(where, "actor like ?")
		args = append(args, "%"+actor+"%")
	}
	if raw, ok := auditBoundary(queryValues.Get("from"), false); ok {
		where = append(where, "datetime(ts) >= datetime(?)")
		args = append(args, raw)
	}
	if raw, ok := auditBoundary(queryValues.Get("to"), true); ok {
		where = append(where, "datetime(ts) <= datetime(?)")
		args = append(args, raw)
	}

	// Category, severity, result and keyword are presentation fields. Fetch a
	// bounded window before filtering so a narrow filter does not unexpectedly
	// return an empty page just because unrelated rows were newer.
	fetchLimit := limit
	if queryValues.Get("category") != "" || queryValues.Get("severity") != "" || queryValues.Get("result") != "" || queryValues.Get("q") != "" {
		fetchLimit = 1000
	}
	query := fmt.Sprintf("select rowid,ts,actor,action,detail from audit where %s order by datetime(ts) desc, rowid desc limit %d", strings.Join(where, " and "), fetchLimit)
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	category := strings.TrimSpace(queryValues.Get("category"))
	severity := strings.TrimSpace(queryValues.Get("severity"))
	result := strings.TrimSpace(queryValues.Get("result"))
	keyword := strings.ToLower(strings.TrimSpace(queryValues.Get("q")))
	if runes := []rune(keyword); len(runes) > 128 {
		keyword = string(runes[:128])
	}
	out := make([]auditRecord, 0, minInt(limit, fetchLimit))
	for rows.Next() {
		var id int64
		var ts, actor, action, detail string
		if err := rows.Scan(&id, &ts, &actor, &action, &detail); err != nil {
			return nil, err
		}
		record := newAuditRecord(id, ts, actor, action, detail)
		if category != "" && category != "all" && record.Category != category {
			continue
		}
		if severity != "" && severity != "all" && record.Severity != severity {
			continue
		}
		if result != "" && result != "all" && record.Result != result {
			continue
		}
		if keyword != "" && !auditContains(record, keyword) {
			continue
		}
		out = append(out, record)
		if len(out) >= limit {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func newAuditRecord(id int64, ts, actor, action, detail string) auditRecord {
	meta := auditMeta(action)
	target := auditTarget(action, detail, meta.result)
	summary := meta.label
	if detail != "" {
		summary += "：" + target
	}
	return auditRecord{
		ID:            id,
		TS:            ts,
		Actor:         actor,
		Action:        action,
		Detail:        detail,
		ActionLabel:   meta.label,
		Category:      meta.category,
		CategoryLabel: auditCategoryLabels[meta.category],
		Severity:      meta.severity,
		SeverityLabel: auditSeverityLabel(meta.severity),
		Result:        meta.result,
		ResultLabel:   auditResultLabel(meta.result),
		Target:        target,
		Summary:       summary,
		System:        actor == "system" || strings.HasPrefix(actor, "agent:"),
	}
}

func auditMeta(action string) auditActionMeta {
	meta := auditActionMeta{label: auditActionLabels[action], category: "other", severity: "info", result: "neutral"}
	if meta.label == "" {
		meta.label = fallbackAuditLabel(action)
	}
	meta.category = auditCategory(action)
	if strings.Contains(action, "failed") || strings.Contains(action, "error") || strings.Contains(action, "denied") || strings.Contains(action, "rate_limited") {
		meta.severity = "warning"
		meta.result = "failure"
	} else if strings.Contains(action, "delete") || strings.Contains(action, "revoke") || strings.Contains(action, "stop") {
		meta.severity = "warning"
		meta.result = "success"
	} else if auditIsSuccessfulAction(action) {
		meta.result = "success"
	}
	if action == "ddns_sync_alert" {
		meta.severity = "warning"
		meta.result = "neutral"
	}
	if strings.Contains(action, "deploy_failed") || action == "certificate_acme_failed" || action == "backup_restore_plan_failed" {
		meta.severity = "critical"
	}
	return meta
}

func auditCategory(action string) string {
	switch {
	case action == "login" || strings.HasPrefix(action, "login_") || action == "password_change" || strings.HasPrefix(action, "user_") || strings.HasPrefix(action, "api_token_"):
		return "auth"
	case strings.HasPrefix(action, "mapping_") || strings.HasPrefix(action, "mapping_groups_") || strings.HasPrefix(action, "port_forward_") || strings.HasPrefix(action, "template_") || strings.HasPrefix(action, "templates_"):
		return "mapping"
	case strings.HasPrefix(action, "http_proxy_"):
		return "proxy"
	case strings.HasPrefix(action, "deploy") || strings.Contains(action, "deploy_failed") || strings.HasPrefix(action, "core_forward_") || strings.HasPrefix(action, "snapshot_"):
		return "config"
	case strings.HasPrefix(action, "wireguard_") || strings.HasPrefix(action, "agent_"):
		return "network"
	case strings.HasPrefix(action, "domain_") || strings.HasPrefix(action, "ddns_") || strings.HasPrefix(action, "certificate_"):
		return "domain"
	case strings.HasPrefix(action, "acl_") || strings.HasPrefix(action, "acls_") || strings.HasPrefix(action, "ip_set_") || strings.HasPrefix(action, "ip_feed_"):
		return "security"
	case strings.HasPrefix(action, "lan_scan_") || strings.HasPrefix(action, "resource_") || strings.HasPrefix(action, "service_") || strings.HasPrefix(action, "mapping_group_"):
		return "inventory"
	case strings.HasPrefix(action, "traffic_") || action == "edge_metrics_read":
		return "traffic"
	case strings.HasPrefix(action, "backup_"):
		return "backup"
	case strings.HasPrefix(action, "ai_"):
		return "assistant"
	case strings.HasPrefix(action, "managed_service_") || strings.HasPrefix(action, "qx_"):
		return "service"
	case strings.HasPrefix(action, "update_") || strings.HasPrefix(action, "webhook_") || strings.HasPrefix(action, "webhooks_") || strings.HasPrefix(action, "alert_"):
		return "system"
	default:
		return "other"
	}
}

func auditIsSuccessfulAction(action string) bool {
	if action == "login" || action == "password_change" || action == "snapshot_rollback" || action == "backup_restore_plan" {
		return true
	}
	for _, verb := range []string{"create", "update", "import", "sync", "issued", "deploy", "generate", "apply", "start", "enable", "disable", "toggle", "acknowledge", "stage", "check", "read", "registered"} {
		if strings.Contains(action, verb) || strings.HasSuffix(action, "_success") {
			return true
		}
	}
	return false
}

func auditTarget(action, detail, result string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		if action == "login" {
			return "登录会话"
		}
		return "系统操作"
	}
	if strings.HasPrefix(action, "port_forward_toggle") {
		id, enabled := parseToggleDetail(detail)
		if id != "" && enabled != "" {
			return "转发 #" + id + " · " + enabled
		}
	}
	if strings.HasPrefix(action, "port_forward_batch_toggle") {
		return normalizeAuditDetail(detail)
	}
	if strings.HasPrefix(action, "mapping_bulk_") {
		if count := detail; count != "" {
			return "共 " + count + " 条映射"
		}
	}
	if action == "deploy_success" || action == "snapshot_generate" || action == "snapshot_rollback" {
		return "配置版本 " + detail
	}
	if result == "failure" {
		if index := strings.Index(detail, ": "); index > 0 {
			return strings.TrimSpace(detail[:index])
		}
		return "系统操作"
	}
	return normalizeAuditDetail(detail)
}

func parseToggleDetail(detail string) (string, string) {
	parts := strings.Fields(detail)
	var id, enabled string
	for _, part := range parts {
		keyValue := strings.SplitN(part, "=", 2)
		if len(keyValue) != 2 {
			continue
		}
		switch keyValue[0] {
		case "id":
			id = keyValue[1]
		case "enabled":
			if keyValue[1] == "true" {
				enabled = "已启用"
			} else if keyValue[1] == "false" {
				enabled = "已停用"
			}
		}
	}
	return id, enabled
}

func normalizeAuditDetail(detail string) string {
	detail = strings.TrimSpace(detail)
	if strings.HasPrefix(detail, "mode=") {
		return strings.ReplaceAll(detail, "mode=", "扫描模式：")
	}
	return detail
}

func auditContains(record auditRecord, keyword string) bool {
	for _, value := range []string{record.Actor, record.Action, record.ActionLabel, record.CategoryLabel, record.Detail, record.Target, record.Summary} {
		if strings.Contains(strings.ToLower(value), keyword) {
			return true
		}
	}
	return false
}

func auditBoundary(raw string, endOfDay bool) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 64 {
		return "", false
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed.UTC().Format(time.RFC3339), true
	}
	if parsed, err := time.Parse("2006-01-02", raw); err == nil {
		if endOfDay {
			parsed = parsed.Add(24*time.Hour - time.Nanosecond)
		}
		return parsed.UTC().Format(time.RFC3339), true
	}
	return "", false
}

func auditSeverityLabel(value string) string {
	switch value {
	case "critical":
		return "高风险"
	case "warning":
		return "需关注"
	default:
		return "普通"
	}
}

func auditResultLabel(value string) string {
	switch value {
	case "success":
		return "已完成"
	case "failure":
		return "失败"
	default:
		return "已记录"
	}
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
