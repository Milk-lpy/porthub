package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"porthub/internal/snapshots"
)

type templatePort struct {
	Name       string             `json:"name"`
	Protocol   snapshots.Protocol `json:"protocol"`
	PublicPort int                `json:"public_port"`
	TargetPort int                `json:"target_port"`
}

type builtinTemplate struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Category    string         `json:"category"`
	HighRisk    bool           `json:"high_risk"`
	Warning     string         `json:"warning,omitempty"`
	Ports       []templatePort `json:"ports"`
}

var builtins = []builtinTemplate{
	{ID: "dont-starve-together", Name: "饥荒联机版", Description: "常用双世界 UDP 端口模板，可按实际集群端口修改。", Category: "game", Ports: []templatePort{{Name: "Master", Protocol: snapshots.UDP, PublicPort: 11001, TargetPort: 11001}, {Name: "Caves", Protocol: snapshots.UDP, PublicPort: 11002, TargetPort: 11002}}},
	{ID: "minecraft", Name: "Minecraft Java", Description: "Java 版默认服务端口。", Category: "game", Ports: []templatePort{{Name: "Server", Protocol: snapshots.TCP, PublicPort: 25565, TargetPort: 25565}}},
	{ID: "palworld", Name: "Palworld", Description: "常见 Palworld UDP 端口，保存前可按服务端配置调整。", Category: "game", Ports: []templatePort{{Name: "Game", Protocol: snapshots.UDP, PublicPort: 8211, TargetPort: 8211}, {Name: "Query", Protocol: snapshots.UDP, PublicPort: 27015, TargetPort: 27015}}},
	{ID: "nas-web", Name: "NAS Web", Description: "HTTP/HTTPS 管理或应用入口。", Category: "nas", Ports: []templatePort{{Name: "HTTP", Protocol: snapshots.TCP, PublicPort: 8088, TargetPort: 80}, {Name: "HTTPS", Protocol: snapshots.TCP, PublicPort: 8443, TargetPort: 443}}},
	{ID: "remote-admin", Name: "远程管理", Description: "SSH/RDP 等高风险入口，默认生成禁用规则。", Category: "admin", HighRisk: true, Warning: "不建议直接暴露到公网。请优先使用 WireGuard 私网访问，或至少配置 IP 白名单。", Ports: []templatePort{{Name: "SSH", Protocol: snapshots.TCP, PublicPort: 2222, TargetPort: 22}, {Name: "RDP", Protocol: snapshots.TCP, PublicPort: 33890, TargetPort: 3389}}},
}

func builtinTemplates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, builtins)
}

func applyTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var x struct {
		TemplateID    string `json:"template_id"`
		Name          string `json:"name"`
		TargetIP      string `json:"target_ip"`
		Enabled       bool   `json:"enabled"`
		AllowHighRisk bool   `json:"allow_high_risk"`
	}
	json.NewDecoder(r.Body).Decode(&x)
	tpl, err := findTemplate(x.TemplateID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	enabled := x.Enabled
	if tpl.HighRisk && !x.AllowHighRisk {
		enabled = false
	}
	var additions []snapshots.Mapping
	for _, p := range tpl.Ports {
		additions = append(additions, snapshots.Mapping{
			Name:        x.Name + " - " + p.Name,
			TargetIP:    x.TargetIP,
			PublicStart: p.PublicPort,
			PublicEnd:   p.PublicPort,
			TargetStart: p.TargetPort,
			TargetEnd:   p.TargetPort,
			Protocol:    p.Protocol,
			Enabled:     enabled,
		})
	}
	all := append(loadMappings(0), additions...)
	if err := snapshots.ValidateMappings(all); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, m := range additions {
		_, err = insertMapping(tx, m, actor(r), false)
		if err != nil {
			tx.Rollback()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	tx.Commit()
	audit(actor(r), "template_apply", tpl.ID)
	writeJSON(w, map[string]any{"ok": true, "created": len(additions), "enabled": enabled, "high_risk": tpl.HighRisk, "warning": tpl.Warning})
}

func findTemplate(id string) (builtinTemplate, error) {
	for _, t := range builtins {
		if t.ID == id {
			return t, nil
		}
	}
	return builtinTemplate{}, errors.New("template not found")
}
