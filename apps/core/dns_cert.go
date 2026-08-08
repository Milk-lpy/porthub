package main

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var dnsNamePattern = regexp.MustCompile(`(?i)^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

type domainItem struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Zone      string `json:"zone"`
	Provider  string `json:"provider"`
	ManagedBy string `json:"managed_by"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type ddnsProviderItem struct {
	ID        int               `json:"id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Config    json.RawMessage   `json:"config,omitempty"`
	SecretRef string            `json:"secret_ref,omitempty"`
	Secret    map[string]string `json:"secret,omitempty"`
	Enabled   bool              `json:"enabled"`
	CreatedAt string            `json:"created_at"`
	UpdatedAt string            `json:"updated_at"`
}

type ddnsRecordItem struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	FQDN           string `json:"fqdn"`
	ProviderID     int    `json:"provider_id"`
	RecordType     string `json:"record_type"`
	IPSource       string `json:"ip_source"`
	LastValue      string `json:"last_value"`
	TTL            int    `json:"ttl"`
	Enabled        bool   `json:"enabled"`
	ManagedByLucky bool   `json:"managed_by_lucky"`
	Interval       int    `json:"interval_seconds"`
	LastSyncAt     string `json:"last_sync_at,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	FailureCount   int    `json:"failure_count"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
	// Lucky-style extensions
	IPURLs        []string `json:"ip_urls,omitempty"`
	NetInterface  string   `json:"net_interface,omitempty"`
	IPRegex       string   `json:"ip_regex,omitempty"`
	ManualIP      string   `json:"manual_ip,omitempty"`
	ForceInterval int      `json:"force_interval_seconds,omitempty"`
	NotifyWebhook string   `json:"notify_webhook,omitempty"`
	VerifyDNS     bool     `json:"verify_dns,omitempty"`
}

type certificateItem struct {
	ID            int      `json:"id"`
	Name          string   `json:"name"`
	Domains       []string `json:"domains"`
	Issuer        string   `json:"issuer"`
	Mode          string   `json:"mode"`
	Status        string   `json:"status"`
	ExpiresAt     string   `json:"expires_at"`
	KeyRef        string   `json:"key_ref,omitempty"`
	DNSProviderID int      `json:"dns_provider_id,omitempty"`
	Enabled       bool     `json:"enabled"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
}

func domains(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var item domainItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		normalizeDomainItem(&item)
		if err := validateDomainItem(item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now().Format(time.RFC3339)
		_, err := db.Exec("insert into domains(name,zone,provider,managed_by,enabled,created_at,updated_at) values(?,?,?,?,?,?,?)", item.Name, item.Zone, item.Provider, item.ManagedBy, boolInt(item.Enabled), now, now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit(actor(r), "domain_create", item.Zone)
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		var item domainItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if item.ID < 1 {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		normalizeDomainItem(&item)
		if err := validateDomainItem(item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now().Format(time.RFC3339)
		db.Exec("update domains set name=?,zone=?,provider=?,managed_by=?,enabled=?,updated_at=? where id=?", item.Name, item.Zone, item.Provider, item.ManagedBy, boolInt(item.Enabled), now, item.ID)
		audit(actor(r), "domain_update", strconv.Itoa(item.ID))
		writeJSON(w, map[string]any{"ok": true})
	case http.MethodDelete:
		deleteByID(w, r, "domains", "domain_delete")
	default:
		rows, _ := db.Query("select id,name,zone,provider,managed_by,enabled,created_at,updated_at from domains order by id desc")
		defer rows.Close()
		var out []domainItem
		for rows.Next() {
			var item domainItem
			var enabled int
			rows.Scan(&item.ID, &item.Name, &item.Zone, &item.Provider, &item.ManagedBy, &enabled, &item.CreatedAt, &item.UpdatedAt)
			item.Enabled = enabled == 1
			out = append(out, item)
		}
		writeJSON(w, out)
	}
}

func ddnsProviders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var item ddnsProviderItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		normalizeProviderItem(&item)
		if err := validateProviderItem(item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		secretRef, err := providerSecretFromItem(&item)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		item.Config = redactProviderConfig(item.Config)
		now := time.Now().Format(time.RFC3339)
		_, err = db.Exec("insert into ddns_providers(name,type,config,secret_ref,enabled,created_at,updated_at) values(?,?,?,?,?,?,?)", item.Name, item.Type, string(item.Config), secretRef, boolInt(item.Enabled), now, now)
		if err != nil {
			// Compensate: the secret file was written above but the record
			// could not be created — remove the freshly written file so no
			// dangling credential is left on disk.
			if secretRef != "" {
				removeProviderSecretFile(secretRef)
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit(actor(r), "ddns_provider_create", item.Name)
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		var item ddnsProviderItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if item.ID < 1 {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		normalizeProviderItem(&item)
		if err := validateProviderItem(item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		secretRef, err := providerSecretFromItem(&item)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		item.Config = redactProviderConfig(item.Config)
		var oldRef string
		db.QueryRow("select coalesce(secret_ref,'') from ddns_providers where id=?", item.ID).Scan(&oldRef)
		if secretRef == "" {
			// Preserve existing secret_ref when neither a new secret nor a
			// path was provided (e.g. editing only non-secret fields).
			secretRef = oldRef
		}
		now := time.Now().Format(time.RFC3339)
		// Commit the database change FIRST, then clean up the previous
		// secret file. If the update fails, the old file is kept (the record
		// still references it) and a freshly written secret file is removed
		// so no dangling credential lingers on disk.
		_, dbErr := db.Exec("update ddns_providers set name=?,type=?,config=?,secret_ref=?,enabled=?,updated_at=? where id=?", item.Name, item.Type, string(item.Config), secretRef, boolInt(item.Enabled), now, item.ID)
		if dbErr != nil {
			if secretRef != "" && secretRef != oldRef {
				removeProviderSecretFile(secretRef)
			}
			http.Error(w, "database update failed: "+dbErr.Error(), http.StatusInternalServerError)
			return
		}
		if oldRef != "" && oldRef != secretRef {
			removeProviderSecretFile(oldRef)
		}
		audit(actor(r), "ddns_provider_update", strconv.Itoa(item.ID))
		writeJSON(w, map[string]any{"ok": true})
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		var oldRef string
		db.QueryRow("select coalesce(secret_ref,'') from ddns_providers where id=?", id).Scan(&oldRef)
		// Delete the database row first; only remove the secret file after
		// the delete committed, so a failed delete never loses credentials.
		if _, dbErr := db.Exec("delete from ddns_providers where id=?", id); dbErr != nil {
			http.Error(w, "database delete failed: "+dbErr.Error(), http.StatusInternalServerError)
			return
		}
		if oldRef != "" {
			removeProviderSecretFile(oldRef)
		}
		audit(actor(r), "ddns_provider_delete", id)
		writeJSON(w, map[string]any{"ok": true})
	default:
		rows, _ := db.Query("select id,name,type,config,secret_ref,enabled,created_at,updated_at from ddns_providers order by id desc")
		defer rows.Close()
		writeJSON(w, scanDDNSProviders(rows))
	}
}

func ddnsRecords(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var item ddnsRecordItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		normalizeDDNSRecord(&item)
		if err := validateDDNSRecord(item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now().Format(time.RFC3339)
		urlsJSON, _ := json.Marshal(item.IPURLs)
		_, err := db.Exec(`insert into ddns_records(name,fqdn,provider_id,record_type,ip_source,last_value,ttl,enabled,managed_by_lucky,interval_seconds,
			ip_urls,net_interface,ip_regex,force_interval_seconds,notify_webhook,verify_dns,manual_ip,created_at,updated_at)
			values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, item.Name, item.FQDN, item.ProviderID, item.RecordType, item.IPSource, item.LastValue, item.TTL,
			boolInt(item.Enabled), boolInt(item.ManagedByLucky), item.Interval,
			string(urlsJSON), item.NetInterface, item.IPRegex, item.ForceInterval, item.NotifyWebhook, boolInt(item.VerifyDNS), item.ManualIP, now, now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit(actor(r), "ddns_record_create", item.FQDN)
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		var item ddnsRecordItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if item.ID < 1 {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		normalizeDDNSRecord(&item)
		if err := validateDDNSRecord(item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now().Format(time.RFC3339)
		urlsJSON, _ := json.Marshal(item.IPURLs)
		db.Exec(`update ddns_records set name=?,fqdn=?,provider_id=?,record_type=?,ip_source=?,last_value=?,ttl=?,enabled=?,managed_by_lucky=?,interval_seconds=?,
			ip_urls=?,net_interface=?,ip_regex=?,force_interval_seconds=?,notify_webhook=?,verify_dns=?,manual_ip=?,updated_at=? where id=?`,
			item.Name, item.FQDN, item.ProviderID, item.RecordType, item.IPSource, item.LastValue, item.TTL, boolInt(item.Enabled), boolInt(item.ManagedByLucky), item.Interval,
			string(urlsJSON), item.NetInterface, item.IPRegex, item.ForceInterval, item.NotifyWebhook, boolInt(item.VerifyDNS), item.ManualIP, now, item.ID)
		audit(actor(r), "ddns_record_update", strconv.Itoa(item.ID))
		writeJSON(w, map[string]any{"ok": true})
	case http.MethodDelete:
		deleteByID(w, r, "ddns_records", "ddns_record_delete")
	default:
		rows, _ := db.Query(`select id,name,fqdn,provider_id,record_type,ip_source,last_value,ttl,enabled,managed_by_lucky,
			coalesce(interval_seconds,300),coalesce(last_sync_at,''),coalesce(last_error,''),coalesce(failure_count,0),created_at,updated_at,
			coalesce(ip_urls,'[]'),coalesce(net_interface,''),coalesce(ip_regex,''),coalesce(force_interval_seconds,0),coalesce(notify_webhook,''),coalesce(verify_dns,0),coalesce(manual_ip,'')
			from ddns_records order by id desc`)
		defer rows.Close()
		var out []ddnsRecordItem
		for rows.Next() {
			var item ddnsRecordItem
			var enabled, lucky, verify int
			var urlsJSON string
			rows.Scan(&item.ID, &item.Name, &item.FQDN, &item.ProviderID, &item.RecordType, &item.IPSource, &item.LastValue, &item.TTL, &enabled, &lucky,
				&item.Interval, &item.LastSyncAt, &item.LastError, &item.FailureCount, &item.CreatedAt, &item.UpdatedAt,
				&urlsJSON, &item.NetInterface, &item.IPRegex, &item.ForceInterval, &item.NotifyWebhook, &verify, &item.ManualIP)
			item.Enabled = enabled == 1
			item.ManagedByLucky = lucky == 1
			item.VerifyDNS = verify == 1
			if urlsJSON != "" {
				_ = json.Unmarshal([]byte(urlsJSON), &item.IPURLs)
			}
			out = append(out, item)
		}
		writeJSON(w, out)
	}
}

func certificates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var item certificateItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		normalizeCertificateItem(&item)
		if err := validateCertificateItem(item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		domainsJSON, _ := json.Marshal(item.Domains)
		now := time.Now().Format(time.RFC3339)
		_, err := db.Exec("insert into certificates(name,domains,issuer,mode,status,expires_at,key_ref,dns_provider_id,enabled,created_at,updated_at) values(?,?,?,?,?,?,?,?,?,?,?)", item.Name, string(domainsJSON), item.Issuer, item.Mode, item.Status, item.ExpiresAt, item.KeyRef, item.DNSProviderID, boolInt(item.Enabled), now, now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit(actor(r), "certificate_create", item.Name)
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		var item certificateItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if item.ID < 1 {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		normalizeCertificateItem(&item)
		if err := validateCertificateItem(item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		domainsJSON, _ := json.Marshal(item.Domains)
		now := time.Now().Format(time.RFC3339)
		db.Exec("update certificates set name=?,domains=?,issuer=?,mode=?,status=?,expires_at=?,key_ref=?,dns_provider_id=?,enabled=?,updated_at=? where id=?", item.Name, string(domainsJSON), item.Issuer, item.Mode, item.Status, item.ExpiresAt, item.KeyRef, item.DNSProviderID, boolInt(item.Enabled), now, item.ID)
		audit(actor(r), "certificate_update", strconv.Itoa(item.ID))
		writeJSON(w, map[string]any{"ok": true})
	case http.MethodDelete:
		deleteByID(w, r, "certificates", "certificate_delete")
	default:
		rows, _ := db.Query("select id,name,domains,issuer,mode,status,expires_at,key_ref,coalesce(dns_provider_id,0),enabled,created_at,updated_at from certificates order by id desc")
		defer rows.Close()
		var out []certificateItem
		for rows.Next() {
			var item certificateItem
			var domainsText string
			var enabled int
			rows.Scan(&item.ID, &item.Name, &domainsText, &item.Issuer, &item.Mode, &item.Status, &item.ExpiresAt, &item.KeyRef, &item.DNSProviderID, &enabled, &item.CreatedAt, &item.UpdatedAt)
			json.Unmarshal([]byte(domainsText), &item.Domains)
			item.Enabled = enabled == 1
			out = append(out, item)
		}
		writeJSON(w, out)
	}
}

func scanDDNSProviders(rows *sql.Rows) []ddnsProviderItem {
	var out []ddnsProviderItem
	for rows.Next() {
		var item ddnsProviderItem
		var enabled int
		var config string
		rows.Scan(&item.ID, &item.Name, &item.Type, &config, &item.SecretRef, &enabled, &item.CreatedAt, &item.UpdatedAt)
		item.Config = redactProviderConfig(json.RawMessage(config))
		item.SecretRef = "" // never expose the secret file path in API responses
		item.Enabled = enabled == 1
		out = append(out, item)
	}
	return out
}

func validateDomainItem(item domainItem) error {
	if strings.TrimSpace(item.Name) == "" {
		return errText("name required")
	}
	if !validDNSName(item.Zone) {
		return errText("valid zone required")
	}
	if !validProviderType(item.Provider) {
		return errText("unsupported provider")
	}
	if item.ManagedBy == "" {
		return nil
	}
	if item.ManagedBy != "porthub" && item.ManagedBy != "external" {
		return errText("managed_by must be porthub or external")
	}
	return nil
}

func normalizeDomainItem(item *domainItem) {
	item.Name = strings.TrimSpace(item.Name)
	item.Zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(item.Zone)), ".")
	item.Provider = strings.ToLower(strings.TrimSpace(item.Provider))
	if item.Provider == "" {
		item.Provider = "external"
	}
	item.ManagedBy = strings.ToLower(strings.TrimSpace(item.ManagedBy))
	if item.ManagedBy == "" {
		item.ManagedBy = "porthub"
	}
}

func validateProviderItem(item ddnsProviderItem) error {
	if strings.TrimSpace(item.Name) == "" {
		return errText("name required")
	}
	if !validProviderType(item.Type) {
		return errText("unsupported provider")
	}
	if item.Type == "webhook" {
		var cfg map[string]any
		if len(item.Config) > 0 && json.Unmarshal(item.Config, &cfg) == nil {
			if endpoint, _ := cfg["endpoint"].(string); endpoint != "" {
				u, err := url.Parse(endpoint)
				if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
					return errText("valid webhook endpoint required")
				}
			}
		}
	}
	return nil
}

func normalizeProviderItem(item *ddnsProviderItem) {
	item.Name = strings.TrimSpace(item.Name)
	item.Type = strings.ToLower(strings.TrimSpace(item.Type))
}

func validateDDNSRecord(item ddnsRecordItem) error {
	if strings.TrimSpace(item.Name) == "" {
		return errText("name required")
	}
	if !validDNSName(item.FQDN) {
		return errText("valid fqdn required")
	}
	if item.ProviderID < 1 {
		return errText("provider_id required")
	}
	if item.RecordType == "" {
		item.RecordType = "A"
	}
	if item.RecordType != "A" && item.RecordType != "AAAA" {
		return errText("record_type must be A or AAAA")
	}
	if item.LastValue != "" && net.ParseIP(item.LastValue) == nil {
		return errText("last_value must be an IP address")
	}
	if item.TTL != 0 && (item.TTL < 60 || item.TTL > 86400) {
		return errText("ttl must be between 60 and 86400")
	}
	if item.Interval != 0 && (item.Interval < 60 || item.Interval > 86400) {
		return errText("interval_seconds must be between 60 and 86400")
	}
	if item.ForceInterval != 0 && (item.ForceInterval < 60 || item.ForceInterval > 604800) {
		return errText("force_interval_seconds must be between 60 and 604800")
	}
	for _, rawURL := range item.IPURLs {
		u, err := url.Parse(rawURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return errText("ip_urls entries must be valid http(s) URLs")
		}
	}
	if strings.TrimSpace(item.IPRegex) != "" {
		if _, err := regexp.Compile(item.IPRegex); err != nil {
			return errText("invalid ip_regex")
		}
	}
	if strings.TrimSpace(item.NotifyWebhook) != "" {
		if _, err := parseDDNSNotify(item.NotifyWebhook); err != nil {
			return errText(err.Error())
		}
	}
	if item.IPSource == "" {
		return nil
	}
	switch item.IPSource {
	case "edge_public", "core_public", "public_api", "net_interface", "interface", "manual", "webhook":
		if item.IPSource == "manual" {
			if ip := net.ParseIP(strings.TrimSpace(item.ManualIP)); ip == nil {
				return errText("manual ip_source requires a valid manual_ip")
			}
			if item.RecordType == "A" && net.ParseIP(strings.TrimSpace(item.ManualIP)).To4() == nil {
				return errText("A record requires an IPv4 manual_ip")
			}
			if item.RecordType == "AAAA" && net.ParseIP(strings.TrimSpace(item.ManualIP)).To4() != nil {
				return errText("AAAA record requires an IPv6 manual_ip")
			}
		}
		return nil
	default:
		return errText("unsupported ip_source")
	}
}

func normalizeDDNSRecord(item *ddnsRecordItem) {
	item.Name = strings.TrimSpace(item.Name)
	item.FQDN = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(item.FQDN)), ".")
	item.RecordType = strings.ToUpper(strings.TrimSpace(item.RecordType))
	if item.RecordType == "" {
		item.RecordType = "A"
	}
	item.IPSource = strings.ToLower(strings.TrimSpace(item.IPSource))
	if item.IPSource == "" {
		item.IPSource = "edge_public"
	}
	item.ManagedByLucky = false
	if item.TTL == 0 {
		item.TTL = 600
	}
	if item.Interval == 0 {
		item.Interval = 300
	}
	item.NetInterface = strings.TrimSpace(item.NetInterface)
	item.IPRegex = strings.TrimSpace(item.IPRegex)
	item.NotifyWebhook = strings.TrimSpace(item.NotifyWebhook)
	item.ManualIP = strings.TrimSpace(item.ManualIP)
}

func validateCertificateItem(item certificateItem) error {
	if strings.TrimSpace(item.Name) == "" {
		return errText("name required")
	}
	if len(item.Domains) == 0 {
		return errText("at least one domain required")
	}
	for _, name := range item.Domains {
		if !validCertificateDNSName(name) {
			return errText("valid certificate domain required")
		}
	}
	if item.Mode == "" {
		item.Mode = "manual"
	}
	if item.Mode != "manual" && item.Mode != "acme_http_01" && item.Mode != "acme_dns_01" {
		return errText("unsupported certificate mode")
	}
	if item.Mode == "acme_dns_01" && item.DNSProviderID < 1 {
		return errText("dns_provider_id required for DNS-01")
	}
	if item.Status == "" {
		return nil
	}
	switch item.Status {
	case "draft", "prepared", "issued", "valid", "failed", "expired", "renew_failed", "external":
		return nil
	default:
		return errText("unsupported certificate status")
	}
}

func normalizeCertificateItem(item *certificateItem) {
	item.Name = strings.TrimSpace(item.Name)
	for i := range item.Domains {
		item.Domains[i] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(item.Domains[i])), ".")
	}
	item.Issuer = strings.TrimSpace(item.Issuer)
	item.Mode = strings.ToLower(strings.TrimSpace(item.Mode))
	if item.Mode == "" {
		item.Mode = "manual"
	}
	item.Status = strings.ToLower(strings.TrimSpace(item.Status))
	if item.Status == "" {
		item.Status = "draft"
	}
}

func redactProviderConfig(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return json.RawMessage(`{}`)
	}
	for _, key := range []string{"token", "secret", "access_key", "access_secret", "api_key", "password", "secret_key", "secret_id"} {
		if _, ok := cfg[key]; ok {
			cfg[key] = "********"
		}
	}
	out, _ := json.Marshal(cfg)
	return out
}

func validDNSName(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	return len(name) > 0 && len(name) <= 253 && dnsNamePattern.MatchString(name)
}

func validCertificateDNSName(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if strings.HasPrefix(name, "*.") {
		return validDNSName(strings.TrimPrefix(name, "*."))
	}
	return validDNSName(name)
}

func validProviderType(provider string) bool {
	switch provider {
	case "cloudflare", "aliyun", "tencent", "huawei", "baidu", "porkbun", "webhook", "external":
		return true
	default:
		return false
	}
}

func deleteByID(w http.ResponseWriter, r *http.Request, table, action string) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	db.Exec("delete from "+table+" where id=?", id)
	audit(actor(r), action, id)
	writeJSON(w, map[string]any{"ok": true})
}

type errText string

func (e errText) Error() string { return string(e) }
