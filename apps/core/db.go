package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"log"
	"os"
	"porthub/internal/auth"
	"strings"
)

func initDB(data string) {
	migrations := []string{
		`create table if not exists users(id integer primary key, username text unique, passhash text, totp text, role text default 'super_admin', must_change int)`,
		`create table if not exists sessions(id text primary key, username text, csrf text, expires_at integer)`,
		`create table if not exists trusted_devices(id integer primary key, username text, token_hash text unique, user_agent text, created_at text, expires_at integer, last_used_at text, revoked int default 0)`,
		strings.Replace(mappingTableDDL, "create table mappings", "create table if not exists mappings", 1),
		`create table if not exists audit(ts text, actor text, action text, detail text)`,
		`create table if not exists resources(id integer primary key, name text, description text, data text, enabled int, created_at text, updated_at text)`,
		`create table if not exists services(id integer primary key, name text, description text, data text, enabled int, created_at text, updated_at text)`,
		`create table if not exists mapping_groups(id integer primary key, name text, description text, data text, enabled int, created_at text, updated_at text)`,
		`create table if not exists acls(id integer primary key, name text, description text, data text, enabled int, created_at text, updated_at text)`,
		`create table if not exists templates(id integer primary key, name text, description text, data text, enabled int, created_at text, updated_at text)`,
		`create table if not exists api_tokens(id integer primary key, name text, token_hash text, prefix text, role text, created_at text, last_used_at text, revoked int)`,
		`create table if not exists webhooks(id integer primary key, name text, description text, data text, enabled int, created_at text, updated_at text)`,
		`create table if not exists acl_rules(id integer primary key, name text, action text, cidr text, enabled int, protocols text, port_start int, port_end int, node_ids text, service_ids text, group_ids text, weekdays text, start_time text, end_time text, timezone text, created_at text, updated_at text)`,
		`create table if not exists http_proxies(id integer primary key, name text, host text, path text, target text, enabled int, force_tls int, created_at text, updated_at text)`,
		`create table if not exists traffic_samples(id integer primary key, ts text, edge_version text, packets integer, bytes integer, raw_json text, rx_bytes integer default 0, tx_bytes integer default 0, rx_bps integer default 0, tx_bps integer default 0, connections integer default 0, cpu_percent real default 0, memory_used integer default 0, memory_total integer default 0)`,
		`create table if not exists traffic_rule_samples(id integer primary key, sample_id integer, ts text, protocol text, port integer, target text, packets integer, bytes integer)`,
		`create table if not exists public_source_audits(id integer primary key, observed_minute text not null, first_seen_at text not null, last_seen_at text not null, edge_version text, source_ip text not null, mapping_id text, mapping text, protocol text, public_port integer, target text, state text, bytes integer default 0, observations integer default 1, timeout_seconds integer default 0)`,
		`create unique index if not exists uq_public_source_audits_bucket on public_source_audits(observed_minute,source_ip,mapping_id,protocol,public_port)`,
		`create index if not exists idx_public_source_audits_source on public_source_audits(source_ip,last_seen_at)`,
		`create index if not exists idx_public_source_audits_last_seen on public_source_audits(last_seen_at)`,
		`create table if not exists domains(id integer primary key, name text, zone text, provider text, managed_by text, enabled int, created_at text, updated_at text)`,
		`create table if not exists ddns_providers(id integer primary key, name text, type text, config text, secret_ref text, enabled int, created_at text, updated_at text)`,
		`create table if not exists ddns_records(id integer primary key, name text, fqdn text, provider_id int, record_type text, ip_source text, last_value text, ttl int, enabled int, managed_by_lucky int, created_at text, updated_at text)`,
		`create table if not exists certificates(id integer primary key, name text, domains text, issuer text, mode text, status text, expires_at text, key_ref text, dns_provider_id int default 0, enabled int, created_at text, updated_at text)`,
		`create table if not exists ip_sets(id integer primary key, name text, kind text, action text, cidrs text, enabled int, created_at text, updated_at text)`,
		`create table if not exists snapshot_history(id integer primary key, version integer unique, created_at text, operator text, sha256 text, status text, result text, source_version integer default 0, payload text)`,
		`create table if not exists agent_enrollments(id integer primary key, name text, token_hash text unique, created_at text, expires_at integer, used_at text, used_by text)`,
		`create table if not exists agent_nodes(node_id text primary key, name text, os text, arch text, version text, address text, status_json text, discovery_json text, certificate_expires_at text, first_seen_at text, last_seen_at text, enabled int default 1)`,
		`create table if not exists wireguard_peers(id integer primary key, node_id text, name text, public_key text unique, address text unique, allowed_ips text, keepalive int default 25, enabled int default 1, created_at text, updated_at text)`,
		`create table if not exists system_alerts(id integer primary key, fingerprint text unique, severity text, source text, title text, detail text, first_seen_at text, last_seen_at text, active int default 1, acknowledged_at text, resolved_at text)`,
		`create table if not exists ip_feeds(id integer primary key, name text, kind text, action text, url text, expected_sha256 text, refresh_hours int default 24, enabled int default 1, ip_set_id int default 0, last_fetch_at text, last_sha256 text, last_error text, created_at text, updated_at text)`,
		`create table if not exists update_events(id integer primary key, ts text, status text, version text, component text, message text)`,
		`create table if not exists lan_scan_runs(id integer primary key, mode text, started_at text, finished_at text, status text, progress integer, total integer, result_json text, error text)`,
		`create table if not exists acme_orders(id integer primary key, certificate_id int, ts text, status text, directory_url text, error text)`,
		`create table if not exists acme_config(id integer primary key check(id=1), email text, updated_at text)`,
		`create table if not exists port_forwards(id integer primary key, name text, node_id text default 'local', listen_family text default 'auto', listen_address text, listen_port_start int, listen_port_end int, protocol text default 'tcp', target_family text default 'auto', target_host text, target_port_start int, target_port_end int, forward_mode text default 'auto', snat_mode text default 'auto', enabled int default 1, acl_id int default 0, allowed_cidrs text default '[]', denied_cidrs text default '[]', rate_limit_kbps int default 0, udp_idle_timeout int default 60, health_check int default 1, last_status text default 'pending', last_error text, created_at text, updated_at text)`,
	}
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			log.Fatal(err)
		}
	}
	compatMigrations()
	seedAdmin(data)
	loadSigningKey(data)
	ensureTLS(data)
	ensureAgentCA(data)
}

func compatMigrations() {
	// SQLite lacks `add column if not exists`; these are intentionally idempotent
	// because duplicate-column failures are harmless during rolling upgrades.
	db.Exec("alter table users add column role text default 'super_admin'")
	db.Exec("alter table users add column must_change int default 1")
	db.Exec("alter table users add column totp_last_counter integer default -1")
	db.Exec("alter table mappings add column acl_ids text")
	for _, column := range []string{
		"description text", "tags text", "resource_id text", "service_id text", "group_id text", "edge_id text",
		"public_ip text", "target_node_id text", "rate_limit_kbps int default 0",
		"connection_limit int default 0", "log_level text default 'info'", "source_mode text default 'compat'",
		"created_by text", "created_at text", "updated_at text",
	} {
		db.Exec("alter table mappings add column " + column)
	}
	for _, column := range []string{
		"targets text", "headers text", "health_path text", "load_balance text default 'round_robin'",
		"websocket int default 1", "preserve_host int default 0",
	} {
		db.Exec("alter table http_proxies add column " + column)
	}
	for _, column := range []string{
		"interval_seconds int default 300", "last_sync_at text", "last_error text", "failure_count int default 0",
	} {
		db.Exec("alter table ddns_records add column " + column)
	}
	for _, column := range []string{
		"ip_urls text", "net_interface text", "ip_regex text", "force_interval_seconds int default 0",
		"notify_webhook text", "verify_dns int default 0", "manual_ip text",
	} {
		db.Exec("alter table ddns_records add column " + column)
	}
	db.Exec("alter table certificates add column dns_provider_id int default 0")
	for _, column := range []string{
		"protocols text", "port_start int default 0", "port_end int default 0", "node_ids text", "service_ids text", "group_ids text",
		"weekdays text", "start_time text", "end_time text", "timezone text",
	} {
		db.Exec("alter table acl_rules add column " + column)
	}
	for _, column := range []string{
		"rx_bytes integer default 0", "tx_bytes integer default 0", "rx_bps integer default 0", "tx_bps integer default 0",
		"connections integer default 0", "cpu_percent real default 0", "memory_used integer default 0", "memory_total integer default 0",
	} {
		db.Exec("alter table traffic_samples add column " + column)
	}
}

func seedAdmin(data string) {
	var n int
	db.QueryRow("select count(*) from users").Scan(&n)
	if n > 0 {
		return
	}
	pw := auth.RandomPassword()
	h, _ := auth.HashPassword(pw)
	sec := auth.NewTOTPSecret()
	db.Exec("insert into users(username,passhash,totp,role,must_change) values(?,?,?,?,1)", "admin", h, sec, "super_admin")
	os.WriteFile(data+"/initial-admin.txt", []byte("username=admin\npassword="+pw+"\ntotp_secret="+sec+"\n"), 0600)
	log.Println("initial admin written to", data+"/initial-admin.txt")
}

func loadSigningKey(data string) {
	if _, err := os.Stat(data + "/ed25519.key"); err != nil {
		pub, pr, _ := ed25519.GenerateKey(rand.Reader)
		os.WriteFile(data+"/ed25519.key", []byte(base64.StdEncoding.EncodeToString(pr)), 0600)
		os.WriteFile(data+"/ed25519.pub", []byte(base64.StdEncoding.EncodeToString(pub)), 0644)
		priv = pr
		return
	}
	b, _ := os.ReadFile(data + "/ed25519.key")
	k, _ := base64.StdEncoding.DecodeString(string(b))
	priv = ed25519.PrivateKey(k)
}

func ensureTLS(data string) {
	if _, err := os.Stat(data + "/tls.crt"); err == nil {
		return
	}
	log.Fatal("missing TLS cert; run deploy script")
}
