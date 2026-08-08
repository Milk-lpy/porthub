package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ProviderField describes one interactive configuration field for a DDNS provider.
// Secret fields are never stored in the config JSON; they are written by the
// backend into the Core secrets directory and referenced via secret_ref.
type ProviderField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Type        string `json:"type"` // text | password | textarea
	Required    bool   `json:"required"`
	Secret      bool   `json:"secret"`
	Default     string `json:"default,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
	Help        string `json:"help,omitempty"`
}

// ProviderSchema describes the interactive form for one provider type.
type ProviderSchema struct {
	Type      string          `json:"type"`
	Label     string          `json:"label"`
	Fields    []ProviderField `json:"fields"`
	Note      string          `json:"note,omitempty"`
	SecretRef string          `json:"secret_ref_hint,omitempty"`
}

func providerSchemas() []ProviderSchema {
	return []ProviderSchema{
		{
			Type:  "cloudflare",
			Label: "Cloudflare",
			Fields: []ProviderField{
				{Key: "zone_id", Label: "Zone ID", Type: "text", Required: true, Placeholder: "如 abc123def456...", Help: "域名 Zone 的 32 位十六进制 ID，可在 Cloudflare 域名概览页找到。"},
				{Key: "token", Label: "API Token", Type: "password", Required: true, Secret: true, Placeholder: "粘贴 API Token", Help: "需具备 Zone.DNS 编辑权限的 API Token。由 Core 加密写入 secrets 目录，不会入库。"},
				{Key: "endpoint_base", Label: "API 端点（可选）", Type: "text", Default: "https://api.cloudflare.com/client/v4", Placeholder: "https://api.cloudflare.com/client/v4"},
			},
			Note: "凭据：API Token（Zone.DNS 编辑权限）。密钥由系统保存到 secrets 目录，仅存引用路径。",
		},
		{
			Type:  "aliyun",
			Label: "阿里云 DNS",
			Fields: []ProviderField{
				{Key: "access_key_id", Label: "AccessKey ID", Type: "text", Required: true, Placeholder: "LTAI...", Help: "阿里云访问密钥 ID，需具有 Alidns 操作权限。"},
				{Key: "access_secret", Label: "AccessKey Secret", Type: "password", Required: true, Secret: true, Placeholder: "粘贴 AccessKey Secret"},
				{Key: "domain_name", Label: "根域名", Type: "text", Required: true, Placeholder: "example.com", Help: "阿里云解析中的一级域名，记录的主机名部分从 FQDN 自动推导。"},
				{Key: "endpoint_base", Label: "API 端点（可选）", Type: "text", Default: "https://alidns.aliyuncs.com", Placeholder: "https://alidns.aliyuncs.com"},
			},
			Note: "凭据：AccessKey ID + Secret（AliyunDNSFullAccess）。密钥由系统保存到 secrets 目录。",
		},
		{
			Type:  "tencent",
			Label: "腾讯云 DNSPod",
			Fields: []ProviderField{
				{Key: "secret_id", Label: "SecretId", Type: "text", Required: true, Placeholder: "AKID...", Help: "腾讯云 API 密钥 ID。"},
				{Key: "secret_key", Label: "SecretKey", Type: "password", Required: true, Secret: true, Placeholder: "粘贴 SecretKey"},
				{Key: "domain", Label: "根域名", Type: "text", Required: true, Placeholder: "example.com", Help: "DNSPod 中的一级域名。"},
				{Key: "record_line", Label: "解析线路（可选）", Type: "text", Default: "默认", Placeholder: "默认"},
				{Key: "endpoint_base", Label: "API 端点（可选）", Type: "text", Default: "https://dnspod.tencentcloudapi.com", Placeholder: "https://dnspod.tencentcloudapi.com"},
			},
			Note: "凭据：SecretId + SecretKey。密钥由系统保存到 secrets 目录。",
		},
		{
			Type:  "huawei",
			Label: "华为云 DNS",
			Fields: []ProviderField{
				{Key: "access_key", Label: "Access Key", Type: "text", Required: true, Placeholder: "AK 字符串", Help: "华为云访问密钥 AK。"},
				{Key: "secret_key", Label: "Secret Key", Type: "password", Required: true, Secret: true, Placeholder: "粘贴 SK"},
				{Key: "domain_name", Label: "根域名", Type: "text", Required: true, Placeholder: "example.com", Help: "华为云解析中的一级域名。"},
				{Key: "zone_id", Label: "Zone ID（可选，留空自动查询）", Type: "text", Placeholder: "自动查询"},
				{Key: "endpoint_base", Label: "API 端点（可选）", Type: "text", Default: "https://dns.myhuaweicloud.com", Placeholder: "https://dns.myhuaweicloud.com"},
			},
			Note: "凭据：AK/SK。密钥由系统保存到 secrets 目录。",
		},
		{
			Type:  "baidu",
			Label: "百度智能云",
			Fields: []ProviderField{
				{Key: "access_key", Label: "Access Key", Type: "text", Required: true, Placeholder: "AK 字符串"},
				{Key: "secret_key", Label: "Secret Key", Type: "password", Required: true, Secret: true, Placeholder: "粘贴 SK"},
				{Key: "domain_name", Label: "根域名", Type: "text", Required: true, Placeholder: "example.com"},
				{Key: "endpoint_base", Label: "API 端点（可选）", Type: "text", Default: "https://bcd.baidubce.com", Placeholder: "https://bcd.baidubce.com"},
			},
			Note: "凭据：AK/SK。密钥由系统保存到 secrets 目录。",
		},
		{
			Type:  "porkbun",
			Label: "Porkbun",
			Fields: []ProviderField{
				{Key: "api_key", Label: "API Key", Type: "password", Required: true, Secret: true, Placeholder: "pk_...", Help: "Porkbun API Key，域名控制面板 API 设置中生成。"},
				{Key: "secret_api_key", Label: "Secret API Key", Type: "password", Secret: true, Placeholder: "sk_...（可选）"},
				{Key: "domain_name", Label: "根域名", Type: "text", Required: true, Placeholder: "example.com"},
				{Key: "endpoint_base", Label: "API 端点（可选）", Type: "text", Default: "https://api.porkbun.com/api/json/v3/dns", Placeholder: "https://api.porkbun.com/api/json/v3/dns"},
			},
			Note: "凭据：API Key + Secret API Key（可仅填 API Key）。密钥由系统保存到 secrets 目录。",
		},
		{
			Type:  "webhook",
			Label: "Webhook",
			Fields: []ProviderField{
				{Key: "endpoint", Label: "Webhook 地址", Type: "text", Required: true, Placeholder: "https://example.com/hook", Help: "收到 POST 请求的端点，URL 中 {fqdn} {ip} {type} 占位符会被替换。"},
				{Key: "template", Label: "请求模板（可选）", Type: "textarea", Placeholder: "{\"fqdn\":\"{fqdn}\",\"ip\":\"{ip}\"}",
					Help: "可选：自定义 JSON 请求体模板。留空则发送 {\"fqdn\":..,\"ip\":..,\"type\":..}。"},
			},
			Note: "Webhook 不涉及云密钥；如需鉴权请在端点侧配置。",
		},
		{
			Type:  "external",
			Label: "外部管理",
			Note:  "DNS 记录由外部系统管理，PortHub 不调用任何 DNS API。无需填写认证凭据。",
		},
	}
}

func providerSchemaHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, providerSchemas())
}

// writeProviderSecret persists interactive secret fields to the Core secrets
// directory and returns the secret_ref path. Multi-value secrets (porkbun)
// are joined with ':' to match the reader format.
func writeProviderSecret(providerType string, secret map[string]string) (string, error) {
	if len(secret) == 0 {
		return "", nil
	}
	base := filepath.Join(dataDir, "secrets")
	if err := os.MkdirAll(base, 0700); err != nil {
		return "", err
	}
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	name := fmt.Sprintf("ddns-%s-%s.key", providerType, hex.EncodeToString(buf))
	path := filepath.Join(base, name)

	var content string
	switch providerType {
	case "tencent":
		secretID := strings.TrimSpace(secret["secret_id"])
		secretKey := strings.TrimSpace(secret["secret_key"])
		if secretID == "" || secretKey == "" {
			return "", errors.New("tencent secret_id and secret_key required")
		}
		encoded, err := json.Marshal(map[string]string{"secret_id": secretID, "secret_key": secretKey})
		if err != nil {
			return "", err
		}
		content = string(encoded)
	case "porkbun":
		apiKey := strings.TrimSpace(secret["api_key"])
		secretKey := strings.TrimSpace(secret["secret_api_key"])
		if apiKey == "" {
			return "", errors.New("porkbun api_key required")
		}
		if secretKey != "" {
			content = apiKey + ":" + secretKey
		} else {
			content = apiKey
		}
	default:
		// Single-secret providers: pick the first non-empty secret value.
		for _, key := range []string{"token", "access_secret", "secret_key", "api_key"} {
			if v := strings.TrimSpace(secret[key]); v != "" {
				content = v
				break
			}
		}
		if content == "" {
			return "", errors.New("no secret value provided")
		}
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return "", err
	}
	return path, nil
}

// providerSecretFromItem extracts secret fields from an incoming provider item
// and stores them, returning the secret_ref path to persist.
func providerSecretFromItem(item *ddnsProviderItem) (string, error) {
	if len(item.Secret) == 0 {
		return item.SecretRef, nil
	}
	if item.Type == "tencent" {
		var config map[string]json.RawMessage
		if json.Unmarshal(item.Config, &config) == nil {
			if secretID := rawString(config["secret_id"]); secretID != "" && secretID != "********" {
				item.Secret["secret_id"] = secretID
			}
		}
	}
	path, err := writeProviderSecret(item.Type, item.Secret)
	if err != nil {
		return "", err
	}
	return path, nil
}

var _ = json.RawMessage{}

// removeProviderSecretFile deletes a secret file owned by this installation,
// i.e. one that lives under the secrets directory. Arbitrary paths supplied
// by the user are left untouched so we never remove files outside our own
// namespace.
func removeProviderSecretFile(ref string) {
	secretsDir := filepath.Join(dataDir, "secrets")
	clean := filepath.Clean(ref)
	if !strings.HasPrefix(clean, secretsDir+string(os.PathSeparator)) {
		return
	}
	_ = os.Remove(clean)
}
