package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type certificatePlanRequest struct {
	CertificateID int `json:"certificate_id"`
}

type certificatePlanResult struct {
	OK              bool     `json:"ok"`
	CertificateID   int      `json:"certificate_id"`
	Name            string   `json:"name"`
	Mode            string   `json:"mode"`
	Domains         []string `json:"domains"`
	RenewalRequired bool     `json:"renewal_required"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
	Steps           []string `json:"steps"`
	Blockers        []string `json:"blockers"`
}

func certificatePlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req certificatePlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.CertificateID < 1 {
		http.Error(w, "certificate_id required", http.StatusBadRequest)
		return
	}
	cert, err := loadCertificate(req.CertificateID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	result := buildCertificatePlan(cert, time.Now())
	audit(actor(r), "certificate_plan", cert.Name)
	writeJSON(w, result)
}

func loadCertificate(id int) (certificateItem, error) {
	var item certificateItem
	var domainsText string
	var enabled int
	err := db.QueryRow("select id,name,domains,issuer,mode,status,expires_at,key_ref,coalesce(dns_provider_id,0),enabled,created_at,updated_at from certificates where id=?", id).Scan(&item.ID, &item.Name, &domainsText, &item.Issuer, &item.Mode, &item.Status, &item.ExpiresAt, &item.KeyRef, &item.DNSProviderID, &enabled, &item.CreatedAt, &item.UpdatedAt)
	json.Unmarshal([]byte(domainsText), &item.Domains)
	item.Enabled = enabled == 1
	return item, err
}

func buildCertificatePlan(cert certificateItem, now time.Time) certificatePlanResult {
	result := certificatePlanResult{OK: true, CertificateID: cert.ID, Name: cert.Name, Mode: cert.Mode, Domains: cert.Domains, ExpiresAt: cert.ExpiresAt}
	if !cert.Enabled {
		result.Blockers = append(result.Blockers, "certificate disabled")
	}
	if err := validateCertificateItem(cert); err != nil {
		result.Blockers = append(result.Blockers, err.Error())
	}
	if cert.KeyRef != "" {
		if err := validateCertificateKeyRef(cert.KeyRef); err != nil {
			result.Blockers = append(result.Blockers, err.Error())
		}
	}
	if cert.Mode == "manual" {
		result.Steps = append(result.Steps, "校验手工导入证书元数据", "检查证书到期时间", "等待用户上传证书和私钥到受保护目录")
	} else {
		result.Steps = append(result.Steps, "创建 ACME 订单", "生成域名授权", "部署 challenge", "等待 CA 验证", "保存证书链和私钥引用", "下发证书引用到 Edge")
	}
	if cert.Mode == "acme_http_01" {
		for _, name := range cert.Domains {
			if strings.HasPrefix(name, "*.") {
				result.Blockers = append(result.Blockers, "wildcard domain requires DNS-01")
				break
			}
		}
		result.Steps = append(result.Steps, "HTTP-01 需要 80/tcp 能从公网访问 Edge")
	}
	if cert.Mode == "acme_dns_01" {
		result.Steps = append(result.Steps, "通过绑定的 DNS Provider 创建短期 TXT 记录", "等待权威 DNS 可见后完成验证", "无论成功失败均清理挑战记录")
	}
	if expiringSoon(cert.ExpiresAt, now) {
		result.RenewalRequired = true
		result.Steps = append(result.Steps, "证书将在 30 天内到期，进入续期窗口")
	}
	result.OK = len(result.Blockers) == 0
	return result
}

func expiringSoon(value string, now time.Time) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	expires, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return false
	}
	return expires.Before(now.Add(30 * 24 * time.Hour))
}

func validateCertificateKeyRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}
	clean, err := filepath.Abs(ref)
	if err != nil {
		return err
	}
	allowed := []string{"/etc/porthub/certs", filepath.Join(dataDir, "certs")}
	ok := false
	for _, base := range allowed {
		baseAbs, _ := filepath.Abs(base)
		if clean == baseAbs || strings.HasPrefix(clean, baseAbs+string(os.PathSeparator)) {
			ok = true
			break
		}
	}
	if !ok {
		return errors.New("key_ref must be under /etc/porthub/certs or Core certs directory")
	}
	return nil
}
