package snapshots

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestSignVerifyAndReplay(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := Sign(Snapshot{Version: 1, CreatedAt: time.Now(), Operator: "t", Mappings: []Mapping{{Name: "ssh", TargetIP: "10.255.0.2", PublicStart: 2222, PublicEnd: 2222, TargetStart: 22, TargetEnd: 22, Protocol: TCP, Enabled: true}}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(s, pub, 0, func(string) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if err := Verify(s, pub, 1, nil); err == nil {
		t.Fatal("expected replay error")
	}
}
func TestPortConflict(t *testing.T) {
	err := ValidateMappings([]Mapping{{Name: "one", TargetIP: "10.0.0.1", PublicStart: 80, PublicEnd: 80, TargetStart: 80, TargetEnd: 80, Protocol: TCP, Enabled: true}, {Name: "two", TargetIP: "10.0.0.2", PublicStart: 80, PublicEnd: 80, TargetStart: 80, TargetEnd: 80, Protocol: TCP, Enabled: true}})
	if err == nil {
		t.Fatal("expected conflict")
	}
}

func TestSamePortOnDifferentListenIPsIsAllowed(t *testing.T) {
	err := ValidateMappings([]Mapping{
		{Name: "one", PublicIP: "192.0.2.10", TargetIP: "10.0.0.1", PublicStart: 443, PublicEnd: 443, TargetStart: 443, TargetEnd: 443, Protocol: TCP, Enabled: true},
		{Name: "two", PublicIP: "192.0.2.11", TargetIP: "10.0.0.2", PublicStart: 443, PublicEnd: 443, TargetStart: 443, TargetEnd: 443, Protocol: TCP, Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSamePortAcrossIPFamiliesIsAllowed(t *testing.T) {
	err := ValidateMappings([]Mapping{
		{Name: "v4", TargetIP: "10.0.0.1", PublicStart: 443, PublicEnd: 443, TargetStart: 443, TargetEnd: 443, Protocol: TCP, Enabled: true},
		{Name: "v6", TargetIP: "fd00::1", PublicStart: 443, PublicEnd: 443, TargetStart: 443, TargetEnd: 443, Protocol: TCP, Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMappingTrafficLimitValidation(t *testing.T) {
	mapping := Mapping{Name: "limited", TargetIP: "10.0.0.1", PublicStart: 443, PublicEnd: 443, TargetStart: 443, TargetEnd: 443, Protocol: TCP, Enabled: true, ConnectionLimit: -1}
	if err := ValidateMappings([]Mapping{mapping}); err == nil {
		t.Fatal("expected negative connection limit rejection")
	}
	mapping.ConnectionLimit = 10
	mapping.LogLevel = "everything"
	if err := ValidateMappings([]Mapping{mapping}); err == nil {
		t.Fatal("expected invalid log level rejection")
	}
}

func TestHTTPProxyConflict(t *testing.T) {
	err := ValidateHTTPProxies([]HTTPProxy{
		{Name: "a", Host: "app.example", Path: "/", Target: "http://10.0.0.1:80", Enabled: true},
		{Name: "b", Host: "app.example", Path: "/", Target: "http://10.0.0.2:80", Enabled: true},
	})
	if err == nil {
		t.Fatal("expected http proxy conflict")
	}
}

func TestHTTPProxyExtendedValidation(t *testing.T) {
	valid := HTTPProxy{Host: "app.example", Path: "/api", Targets: []string{"http://10.0.0.1:80", "http://10.0.0.2:80"},
		Headers: map[string]string{"X-PortHub": "enabled"}, HealthPath: "/health", LoadBalance: "round_robin", Enabled: true}
	if err := ValidateHTTPProxies([]HTTPProxy{valid}); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.Headers = map[string]string{"Bad Header": "value"}
	if err := ValidateHTTPProxies([]HTTPProxy{invalid}); err == nil {
		t.Fatal("invalid header accepted")
	}
	invalid = valid
	invalid.Targets = []string{"http://user:pass@10.0.0.1"}
	if err := ValidateHTTPProxies([]HTTPProxy{invalid}); err == nil {
		t.Fatal("target credentials accepted")
	}
}

func TestValidateIPSets(t *testing.T) {
	if err := ValidateIPSets([]IPSet{{Name: "custom", Kind: "custom", Action: ACLDeny, CIDRs: []string{"203.0.113.0/24", "2001:db8::/32"}, Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateIPSets([]IPSet{{Name: "bad", Kind: "custom", Action: ACLDeny, CIDRs: []string{"bad-cidr"}, Enabled: true}}); err == nil {
		t.Fatal("expected invalid cidr")
	}
	if err := ValidateIPSets([]IPSet{{Name: "bad", Kind: "planet", Action: ACLDeny, CIDRs: []string{"203.0.113.0/24"}, Enabled: true}}); err == nil {
		t.Fatal("expected invalid kind")
	}
}

func TestValidateACLRefs(t *testing.T) {
	err := ValidateACLRefs(
		[]Mapping{{Name: "valid acl", TargetIP: "10.0.0.1", PublicStart: 80, PublicEnd: 80, TargetStart: 80, TargetEnd: 80, Protocol: TCP, Enabled: true, ACLIDs: []string{"1"}}},
		[]ACLRule{{ID: "1", Name: "office", Action: ACLAllow, CIDR: "198.51.100.0/24", Enabled: true}},
	)
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateACLRefs(
		[]Mapping{{Name: "missing acl", TargetIP: "10.0.0.1", PublicStart: 80, PublicEnd: 80, TargetStart: 80, TargetEnd: 80, Protocol: TCP, Enabled: true, ACLIDs: []string{"missing"}}},
		[]ACLRule{{ID: "1", Name: "office", Action: ACLAllow, CIDR: "198.51.100.0/24", Enabled: true}},
	)
	if err == nil {
		t.Fatal("expected missing ACL reference")
	}
}

func TestACLTimeWindowAndRange(t *testing.T) {
	rule := ACLRule{ID: "1", Name: "office", Action: ACLAllow, CIDR: "198.51.100.1-198.51.100.20", Enabled: true,
		Weekdays: []int{1}, StartTime: "23:00", EndTime: "02:00", Timezone: "UTC"}
	if err := ValidateACLRules([]ACLRule{rule}); err != nil {
		t.Fatal(err)
	}
	if !ACLRuleActiveAt(rule, time.Date(2026, 8, 3, 23, 30, 0, 0, time.UTC)) || !ACLRuleActiveAt(rule, time.Date(2026, 8, 3, 1, 0, 0, 0, time.UTC)) {
		t.Fatal("overnight time window was not active")
	}
	if ACLRuleActiveAt(rule, time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)) {
		t.Fatal("time window active at noon")
	}
}
