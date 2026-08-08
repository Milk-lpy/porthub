package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"porthub/internal/nftables"
	"porthub/internal/snapshots"
)

func setupPortForwardTestDB(t *testing.T) {
	t.Helper()
	oldDB := db
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db = testDB
	if _, err := db.Exec(`create table if not exists port_forwards(id integer primary key, name text, node_id text default 'local', listen_family text default 'auto', listen_address text, listen_port_start int, listen_port_end int, protocol text default 'tcp', target_family text default 'auto', target_host text, target_port_start int, target_port_end int, forward_mode text default 'auto', snat_mode text default 'auto', enabled int default 1, acl_id int default 0, allowed_cidrs text default '[]', denied_cidrs text default '[]', rate_limit_kbps int default 0, udp_idle_timeout int default 60, health_check int default 1, last_status text default 'pending', last_error text, created_at text, updated_at text)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`create table if not exists mappings(id integer primary key, name text, description text, tags text, resource_id text, service_id text, group_id text, edge_id text, public_ip text, target_node_id text, target_ip text, public_start int, public_end int, target_start int, target_end int, proto text, enabled int, acl_ids text, rate_limit_kbps int, connection_limit int, log_level text, source_mode text, created_by text, created_at text, updated_at text)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`create table if not exists acl_rules(id integer primary key, name text, action text, cidr text, enabled int, protocols text, port_start int, port_end int, node_ids text, service_ids text, group_ids text, weekdays text, start_time text, end_time text, timezone text, created_at text, updated_at text)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		db = oldDB
	})
}

func TestPortForwardGlobalACLAppliesToWholeRange(t *testing.T) {
	setupPortForwardTestDB(t)
	if _, err := db.Exec(`insert into acl_rules(id,name,action,cidr,enabled,protocols,port_start,port_end,node_ids,service_ids,group_ids,weekdays,start_time,end_time,timezone)
		values(7,'home-only','allow','192.0.2.0/24',1,'[]',0,0,'[]','[]','[]','[]','','','')`); err != nil {
		t.Fatal(err)
	}
	item := portForwardItem{
		ID: 1, Name: "range", ListenFamily: "ipv4", ListenAddress: "0.0.0.0",
		ListenPortStart: 30000, ListenPortEnd: 30002, Protocol: "tcp",
		TargetHost: "10.255.0.2", TargetPortStart: 30000, TargetPortEnd: 30002,
		SNATMode: "masquerade", ACLID: 7,
	}
	rules := portForwardToRule(item)
	if len(rules) != 1 {
		t.Fatalf("expected one ACL-covered segment, got %d", len(rules))
	}
	if len(rules[0].AllowedCIDRs) != 1 || rules[0].AllowedCIDRs[0] != "192.0.2.0/24" {
		t.Fatalf("global ACL not applied: %+v", rules[0].AllowedCIDRs)
	}
}

func TestPortForwardProtocolScopedACLDoesNotApplyToBothRule(t *testing.T) {
	setupPortForwardTestDB(t)
	if _, err := db.Exec(`insert into acl_rules(id,name,action,cidr,enabled,protocols,port_start,port_end,node_ids,service_ids,group_ids,weekdays,start_time,end_time,timezone)
		values(8,'udp-only','deny','198.51.100.0/24',1,'["udp"]',0,0,'[]','[]','[]','[]','','','')`); err != nil {
		t.Fatal(err)
	}
	item := portForwardItem{
		ID: 1, Name: "both", ListenFamily: "ipv4", ListenAddress: "0.0.0.0",
		ListenPortStart: 31000, ListenPortEnd: 31000, Protocol: "both",
		TargetHost: "10.255.0.2", TargetPortStart: 31000, TargetPortEnd: 31000,
		SNATMode: "masquerade", ACLID: 8,
	}
	rules := portForwardToRule(item)
	if len(rules) != 1 || len(rules[0].DeniedCIDRs) != 0 {
		t.Fatalf("protocol-scoped ACL should not be over-applied to both rule: %+v", rules)
	}
}

func TestValidatePortForwardItem(t *testing.T) {
	setupPortForwardTestDB(t)
	base := portForwardItem{
		Name: "test", ListenFamily: "ipv4", ListenAddress: "0.0.0.0",
		ListenPortStart: 20001, ListenPortEnd: 20001, Protocol: "tcp",
		TargetHost: "192.0.2.50", TargetPortStart: 8080, TargetPortEnd: 8080,
		ForwardMode: "auto", SNATMode: "auto", Enabled: true,
	}
	if err := validatePortForwardItem(base, 0); err != nil {
		t.Fatalf("base should be valid: %v", err)
	}
	// Port range length mismatch
	bad := base
	bad.TargetPortEnd = 8081
	if err := validatePortForwardItem(bad, 0); err == nil {
		t.Fatal("expected range length mismatch error")
	}
	// Invalid protocol
	bad = base
	bad.Protocol = "icmp"
	if err := validatePortForwardItem(bad, 0); err == nil {
		t.Fatal("expected protocol error")
	}
	// Cross-family with nft mode must fail
	bad = base
	bad.ListenFamily = "ipv6"
	bad.ListenAddress = "::"
	bad.ForwardMode = "nft"
	bad.TargetHost = "192.0.2.50"
	if err := validatePortForwardItem(bad, 0); err == nil {
		t.Fatal("expected nft cross-family error")
	}
	// Cross-family with auto mode is fine (relay)
	bad.ForwardMode = "auto"
	if err := validatePortForwardItem(bad, 0); err != nil {
		t.Fatalf("auto cross-family should be valid: %v", err)
	}
	// Domain target with nft mode fails, auto/relay ok
	bad = base
	bad.TargetHost = "service.example.com"
	bad.ForwardMode = "nft"
	if err := validatePortForwardItem(bad, 0); err == nil {
		t.Fatal("expected nft domain error")
	}
	bad.ForwardMode = "relay"
	if err := validatePortForwardItem(bad, 0); err != nil {
		t.Fatalf("relay domain should be valid: %v", err)
	}
}

func TestDisabledPortForwardDraftDefersCollisionUntilEnable(t *testing.T) {
	setupPortForwardTestDB(t)
	if _, err := db.Exec(`insert into port_forwards(id,name,listen_family,listen_address,listen_port_start,listen_port_end,protocol,target_family,target_host,target_port_start,target_port_end,forward_mode,snat_mode,enabled)
		values(1,'existing','ipv4','0.0.0.0',24001,24001,'both','ipv4','192.0.2.10',24001,24001,'nft','masquerade',1)`); err != nil {
		t.Fatal(err)
	}
	draft := portForwardItem{
		ID: 2, Name: "migration-draft", ListenFamily: "ipv4", ListenAddress: "0.0.0.0",
		ListenPortStart: 24001, ListenPortEnd: 24001, Protocol: "both",
		TargetFamily: "ipv4", TargetHost: "192.0.2.150", TargetPortStart: 24001, TargetPortEnd: 24001,
		ForwardMode: "nft", SNATMode: "masquerade", Enabled: false,
	}
	if err := validatePortForwardItem(draft, draft.ID); err != nil {
		t.Fatalf("disabled migration draft should be accepted: %v", err)
	}
	draft.Enabled = true
	if err := validatePortForwardItem(draft, draft.ID); err == nil {
		t.Fatal("enabled migration draft must be rejected while the port is occupied")
	}
}

func TestPortForwardSamePortDifferentFamiliesDoNotCollide(t *testing.T) {
	setupPortForwardTestDB(t)
	if _, err := db.Exec(`insert into port_forwards(id,name,listen_family,listen_address,listen_port_start,listen_port_end,protocol,target_family,target_host,target_port_start,target_port_end,forward_mode,snat_mode,enabled)
		values(1,'ipv4','ipv4','0.0.0.0',24101,24101,'both','ipv4','192.0.2.10',24101,24101,'nft','masquerade',1)`); err != nil {
		t.Fatal(err)
	}
	ipv6 := portForwardItem{
		ID: 2, Name: "ipv6", ListenFamily: "ipv6", ListenAddress: "::",
		ListenPortStart: 24101, ListenPortEnd: 24101, Protocol: "both",
		TargetFamily: "ipv4", TargetHost: "192.0.2.150", TargetPortStart: 24101, TargetPortEnd: 24101,
		ForwardMode: "relay", SNATMode: "masquerade", Enabled: true,
	}
	if err := validatePortForwardItem(ipv6, ipv6.ID); err != nil {
		t.Fatalf("same port on IPv4 and IPv6 should be allowed: %v", err)
	}
	ipv4 := ipv6
	ipv4.ID = 3
	ipv4.Name = "another-ipv4"
	ipv4.ListenFamily = "ipv4"
	ipv4.ListenAddress = "0.0.0.0"
	ipv4.ForwardMode = "nft"
	if err := validatePortForwardItem(ipv4, ipv4.ID); err == nil {
		t.Fatal("same-family overlapping port must still collide")
	}
}

func TestPortForwardToggleRechecksDraftCollision(t *testing.T) {
	setupPortForwardTestDB(t)
	for _, statement := range []string{
		`insert into port_forwards(id,name,node_id,listen_family,listen_address,listen_port_start,listen_port_end,protocol,target_family,target_host,target_port_start,target_port_end,forward_mode,snat_mode,enabled,acl_id,allowed_cidrs,denied_cidrs,rate_limit_kbps,udp_idle_timeout,health_check,last_status,created_at,updated_at)
		 values(1,'existing','local','ipv4','0.0.0.0',24002,24002,'both','ipv4','192.0.2.10',24002,24002,'nft','masquerade',1,0,'[]','[]',0,60,1,'applied','now','now')`,
		`insert into port_forwards(id,name,node_id,listen_family,listen_address,listen_port_start,listen_port_end,protocol,target_family,target_host,target_port_start,target_port_end,forward_mode,snat_mode,enabled,acl_id,allowed_cidrs,denied_cidrs,rate_limit_kbps,udp_idle_timeout,health_check,last_status,created_at,updated_at)
		 values(2,'draft','local','ipv4','0.0.0.0',24002,24002,'both','ipv4','192.0.2.150',24002,24002,'nft','masquerade',0,0,'[]','[]',0,60,1,'disabled','now','now')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/port-forwards/toggle", strings.NewReader(`{"id":2,"enabled":true}`))
	recorder := httptest.NewRecorder()
	portForwardToggle(recorder, req)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("toggle status = %d, want %d; body=%s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}
	var enabled int
	if err := db.QueryRow("select enabled from port_forwards where id=2").Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatal("conflicting draft was enabled")
	}
}

func TestPortForwardBatchUpdatesAllSelectedRules(t *testing.T) {
	setupPortForwardTestDB(t)
	insertPortForwardBatchFixture(t, 1, "one", "ipv4", "0.0.0.0", 24201, false)
	insertPortForwardBatchFixture(t, 2, "two", "ipv4", "0.0.0.0", 24202, false)

	count, err := updatePortForwardBatch([]int{1, 2}, true, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
	for _, id := range []int{1, 2} {
		var enabled int
		var status string
		if err := db.QueryRow("select enabled,last_status from port_forwards where id=?", id).Scan(&enabled, &status); err != nil {
			t.Fatal(err)
		}
		if enabled != 1 || status != "pending" {
			t.Fatalf("id %d state = enabled:%d status:%s", id, enabled, status)
		}
	}
}

func TestPortForwardBatchRestoresDatabaseWhenApplyFails(t *testing.T) {
	setupPortForwardTestDB(t)
	insertPortForwardBatchFixture(t, 1, "one", "ipv4", "0.0.0.0", 24301, false)
	insertPortForwardBatchFixture(t, 2, "two", "ipv4", "0.0.0.0", 24302, false)
	calls := 0
	_, err := updatePortForwardBatch([]int{1, 2}, true, func() error {
		calls++
		if calls == 1 {
			return fmt.Errorf("simulated data-plane failure")
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected apply failure")
	}
	if calls != 2 {
		t.Fatalf("apply calls = %d, want 2 (change + rollback)", calls)
	}
	for _, id := range []int{1, 2} {
		var enabled int
		var status string
		if err := db.QueryRow("select enabled,last_status from port_forwards where id=?", id).Scan(&enabled, &status); err != nil {
			t.Fatal(err)
		}
		if enabled != 0 || status != "disabled" {
			t.Fatalf("id %d was not restored: enabled:%d status:%s", id, enabled, status)
		}
	}
}

func TestPortForwardBatchAllowsSamePortAcrossAddressFamilies(t *testing.T) {
	setupPortForwardTestDB(t)
	insertPortForwardBatchFixture(t, 1, "v4", "ipv4", "0.0.0.0", 24401, false)
	insertPortForwardBatchFixture(t, 2, "v6", "ipv6", "::", 24401, false)
	if _, err := updatePortForwardBatch([]int{1, 2}, true, func() error { return nil }); err != nil {
		t.Fatalf("IPv4 and IPv6 pair should batch-enable: %v", err)
	}
}

func TestPortForwardBatchRejectsSelectedRuleConflict(t *testing.T) {
	setupPortForwardTestDB(t)
	insertPortForwardBatchFixture(t, 1, "one", "ipv4", "0.0.0.0", 24501, false)
	insertPortForwardBatchFixture(t, 2, "two", "ipv4", "0.0.0.0", 24501, false)
	if _, err := updatePortForwardBatch([]int{1, 2}, true, func() error { return nil }); err == nil {
		t.Fatal("same-family batch conflict should be rejected")
	}
}

func insertPortForwardBatchFixture(t *testing.T, id int, name, family, address string, port int, enabled bool) {
	t.Helper()
	_, err := db.Exec(`insert into port_forwards(id,name,node_id,listen_family,listen_address,listen_port_start,listen_port_end,protocol,target_family,target_host,target_port_start,target_port_end,forward_mode,snat_mode,enabled,acl_id,allowed_cidrs,denied_cidrs,rate_limit_kbps,udp_idle_timeout,health_check,last_status,last_error,created_at,updated_at)
		values(?,?,?,?,?,?,?,'both','ipv4','192.0.2.150',?,?,'auto','masquerade',?,0,'[]','[]',0,60,1,?,'','now','now')`,
		id, name, "local", family, address, port, port, port, port, boolInt(enabled), map[bool]string{true: "applied", false: "disabled"}[enabled])
	if err != nil {
		t.Fatal(err)
	}
}

func TestEffectiveFamilies(t *testing.T) {
	item := portForwardItem{ListenFamily: "auto", ListenAddress: "::", TargetHost: "192.0.2.50"}
	if got := item.effectiveListenFamily(); got != "ipv6" {
		t.Fatalf("listen family: got %s want ipv6", got)
	}
	if got := item.effectiveTargetFamily(); got != "ipv4" {
		t.Fatalf("target family: got %s want ipv4", got)
	}
	domain := portForwardItem{TargetHost: "host.example.com"}
	if got := domain.effectiveTargetFamily(); got != "auto" {
		t.Fatalf("domain target family: got %s want auto", got)
	}
}

func TestPortRangesAndProtocols(t *testing.T) {
	if !portRangesOverlap(100, 200, 150, 250) {
		t.Fatal("expected overlap")
	}
	if portRangesOverlap(100, 200, 201, 300) {
		t.Fatal("expected no overlap")
	}
	if !protocolsOverlap("both", "tcp") {
		t.Fatal("both should overlap tcp")
	}
	if protocolsOverlap("tcp", "udp") {
		t.Fatal("tcp/udp should not overlap")
	}
}

func TestCompileCoreForwardWithForwards(t *testing.T) {
	cfg := nftables.CoreForwardConfig{
		WGInterface: "wg-porthub", LANInterface: "eth0",
		LANCIDRs:    []*net.IPNet{mustCIDR("192.0.2.0/24")},
		TunnelCIDRs: []*net.IPNet{mustCIDR("10.255.0.0/24")},
	}
	s := snapshots.Snapshot{Mappings: []snapshots.Mapping{{
		ID: "1", Name: "m1", TargetIP: "192.0.2.50", PublicStart: 9000, PublicEnd: 9000,
		TargetStart: 8080, TargetEnd: 8080, Protocol: snapshots.TCP, Enabled: true,
	}}}
	forwards := []nftables.PortForwardRule{{
		ID: 7, ListenFamily: "ipv4", ListenAddress: "0.0.0.0",
		ListenPortStart: 20002, ListenPortEnd: 20002, Protocol: "tcp",
		TargetHost: "192.0.2.60", TargetPortStart: 22, TargetPortEnd: 22, SNATMode: "masquerade",
	}}
	rules, err := nftables.CompileCoreForwardWithForwards(s, forwards, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rules, "chain prerouting") {
		t.Fatal("expected prerouting chain")
	}
	if !strings.Contains(rules, "dnat ip to 192.0.2.60:22") {
		t.Fatalf("missing dnat rule:\n%s", rules)
	}
	if !strings.Contains(rules, "pf:7") {
		t.Fatalf("missing rule comment:\n%s", rules)
	}
	// Cross-family rule must be skipped by the nft compiler.
	forwards = append(forwards, nftables.PortForwardRule{
		ID: 8, ListenFamily: "ipv6", ListenAddress: "::",
		ListenPortStart: 20003, ListenPortEnd: 20003, Protocol: "tcp",
		TargetHost: "192.0.2.70", TargetPortStart: 80, TargetPortEnd: 80,
	})
	rules, err = nftables.CompileCoreForwardWithForwards(s, forwards, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rules, "20003") {
		t.Fatalf("cross-family rule leaked into nft output:\n%s", rules)
	}
}

func TestCompilePortForwardACL(t *testing.T) {
	_, _, dnat, err := nftables.CompilePortForwardRules([]nftables.PortForwardRule{{
		ID: 9, ListenFamily: "ipv4", ListenAddress: "0.0.0.0",
		ListenPortStart: 20004, ListenPortEnd: 20004, Protocol: "both",
		TargetHost: "192.0.2.80", TargetPortStart: 443, TargetPortEnd: 443,
		AllowedCIDRs: []string{"10.0.0.0/8"}, DeniedCIDRs: []string{"203.0.113.0/24"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(dnat, "\n")
	if !strings.Contains(joined, "saddr { 203.0.113.0/24 }") {
		t.Fatalf("missing deny rule:\n%s", joined)
	}
	if !strings.Contains(joined, "saddr { 10.0.0.0/8 }") {
		t.Fatalf("missing allow matcher:\n%s", joined)
	}
}

func TestLiveListenPorts(t *testing.T) {
	ports := liveListenPorts("ipv4")
	// The test process itself listens on nothing, but the system has sshd etc.
	// We only verify the reader does not crash and returns a map.
	if ports == nil {
		t.Fatal("expected a map")
	}
	if len(ports) == 0 {
		t.Log("no live ports detected (expected on isolated CI)")
	}
}

func mustCIDR(value string) *net.IPNet {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		panic(err)
	}
	return network
}

func TestBuildRelayConfigPhaseOne(t *testing.T) {
	setupPortForwardTestDB(t)
	if _, err := db.Exec(`insert into acl_rules(id,name,action,cidr,enabled,protocols,port_start,port_end,node_ids,service_ids,group_ids,weekdays,start_time,end_time,timezone)
		values(9,'home','allow','192.0.2.0/24',1,'[]',0,0,'[]','[]','[]','[]','','','')`); err != nil {
		t.Fatal(err)
	}
	item := portForwardItem{
		ID: 1, Name: "v6tov4", ListenFamily: "ipv6", ListenAddress: "",
		ListenPortStart: 32000, ListenPortEnd: 32000, Protocol: "both",
		TargetHost: "192.0.2.50", TargetPortStart: 8080, TargetPortEnd: 8080,
		ForwardMode: "auto", SNATMode: "auto", Enabled: true, ACLID: 9,
	}
	body, err := buildRelayConfig([]portForwardItem{item})
	if err != nil {
		t.Fatal(err)
	}
	var cfg relayConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("relay config not valid JSON: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 relay rule, got %d", len(cfg.Rules))
	}
	rule := cfg.Rules[0]
	if rule.ListenPortStart != 32000 || rule.ListenPortEnd != 32000 {
		t.Fatalf("unexpected listen ports: %d-%d", rule.ListenPortStart, rule.ListenPortEnd)
	}
	if rule.TargetPortStart != 8080 || rule.TargetPortEnd != 8080 {
		t.Fatalf("unexpected target ports: %d-%d", rule.TargetPortStart, rule.TargetPortEnd)
	}
	if len(rule.AllowedCIDRs) != 1 || rule.AllowedCIDRs[0] != "192.0.2.0/24" {
		t.Fatalf("ACL not resolved into relay rule: %+v", rule.AllowedCIDRs)
	}
}

func TestBuildRelayConfigEmptyRules(t *testing.T) {
	setupPortForwardTestDB(t)
	body, err := buildRelayConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg relayConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("empty relay config must be valid JSON: %v", err)
	}
	if cfg.Rules == nil || len(cfg.Rules) != 0 {
		t.Fatalf("empty config must contain an empty rules array (so listeners close), got %+v", cfg.Rules)
	}
}
