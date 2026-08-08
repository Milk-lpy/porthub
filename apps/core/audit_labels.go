package main

import "strings"

func fallbackAuditLabel(action string) string {
	if action == "" {
		return "未命名操作"
	}
	wordLabels := map[string]string{
		"acl": "ACL", "acls": "ACL", "agent": "Agent", "ai": "助手", "alert": "告警", "api": "API",
		"backup": "备份", "certificate": "证书", "check": "检查", "collect": "采集", "complete": "完成",
		"core": "Core", "create": "新增", "ddns": "DDNS", "delete": "删除", "deploy": "下发", "disable": "停用",
		"domain": "域名", "edge": "Edge", "enable": "启用", "failed": "失败", "feed": "数据源", "generate": "生成",
		"group": "分组", "groups": "分组", "import": "导入", "ip": "IP", "lan": "局域网", "login": "登录",
		"mapping": "映射", "metrics": "指标", "node": "节点", "password": "密码", "peer": "节点",
		"port": "端口", "proxy": "代理", "publish": "发布", "read": "查看", "registered": "注册",
		"resource": "资源", "restore": "恢复", "rollback": "回滚", "rule": "规则", "scan": "扫描",
		"scheduled": "定时", "service": "服务", "set": "集合", "snapshot": "快照", "stage": "准备",
		"start": "启动", "stop": "停止", "success": "成功", "sync": "同步", "template": "模板",
		"templates": "模板", "toggle": "切换", "traffic": "流量", "update": "更新", "user": "用户",
		"webhook": "Webhook", "webhooks": "Webhook", "wireguard": "WireGuard",
	}
	parts := strings.Split(action, "_")
	words := make([]string, 0, len(parts))
	for _, part := range parts {
		if label, ok := wordLabels[part]; ok {
			words = append(words, label)
		} else if part != "" {
			words = append(words, part)
		}
	}
	return strings.Join(words, " ")
}
