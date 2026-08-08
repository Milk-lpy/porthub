package main

import (
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"porthub/internal/nftables"
	"porthub/internal/snapshots"
	"testing"
)

func TestValidateNFTOwnedTableOnly(t *testing.T) {
	valid := "flush table inet porthub_core\ntable inet porthub_core {\n chain forward { type filter hook forward priority 0; policy accept; }\n}\n"
	if err := validateNFT(valid, "porthub_core"); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		"flush ruleset\ntable inet porthub_core {}",
		"table inet filter {}",
		"include \"/etc/passwd\"\ntable inet porthub_core {}",
		"table inet porthub_core {\n}\nadd rule inet filter input accept",
		"add rule inet filter input accept\ntable inet porthub_core {\n}",
		"table inet porthub_core { } add rule inet filter input accept",
		"table inet porthub_core {\n",
	} {
		if err := validateNFT(invalid, "porthub_core"); err == nil {
			t.Fatalf("expected rejection for %q", invalid)
		}
	}
}

func TestValidateNFTRejectsTableEscapeAndHooks(t *testing.T) {
	// C1: closing the owned table then opening another on the same line
	// (net-zero braces) must be rejected.
	escapes := []string{
		"table inet porthub_core {\n chain c { policy accept; }\n}; table inet evil {\n chain x { type filter hook input priority -300; policy drop; }\n}\n",
		"table inet porthub_core {\n}\n; add table inet evil\n",
		"table inet porthub_core { }; add rule inet filter input accept\n",
	}
	for _, e := range escapes {
		if err := validateNFT(e, "porthub_core"); err == nil {
			t.Fatalf("C1: expected rejection for table-escape payload:\n%s", e)
		}
	}
	// C2: host-global base-chain hooks inside the owned table must be rejected.
	hooks := []string{
		"table inet porthub_core {\n chain x { type filter hook input priority 0; policy accept; }\n}\n",
		"table inet porthub_core {\n chain x { type filter hook output priority 0; policy accept; }\n}\n",
		"flush table inet porthub_core\ntable inet porthub_core {\n chain drop { type filter hook forward priority 0; policy drop; }\n}\n",
	}
	for _, h := range hooks {
		if err := validateNFT(h, "porthub_core"); err == nil {
			t.Fatalf("C2: expected rejection for forbidden-hook payload:\n%s", h)
		}
	}
	// L1: tab-separated forbidden directive must still be caught.
	if err := validateNFT("include\t\"/etc/passwd\"\ntable inet porthub_core {}\n", "porthub_core"); err == nil {
		t.Fatal("L1: expected rejection for tab-separated include directive")
	}
}

func TestValidateNFTAcceptsPortHubCompilers(t *testing.T) {
	edgeRules, err := nftables.Compile(snapshots.Snapshot{}, "wg-porthub")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNFT(edgeRules, "porthub"); err != nil {
		t.Fatalf("Edge compiler output rejected: %v", err)
	}
	lan, _ := nftables.ParseCIDRs("192.0.2.0/24")
	tunnel, _ := nftables.ParseCIDRs("10.255.0.0/24")
	coreRules, err := nftables.CompileCoreForward(snapshots.Snapshot{}, nftables.CoreForwardConfig{
		WGInterface: "wg-porthub", LANInterface: "eth0", LANCIDRs: lan, TunnelCIDRs: tunnel,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNFT(coreRules, "porthub_core"); err != nil {
		t.Fatalf("Core compiler output rejected: %v", err)
	}
}

func TestNotifySystemdReady(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if err := notifySystemdReady(); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	count, _, err := listener.ReadFromUnix(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:count]) != "READY=1" {
		t.Fatalf("unexpected notification %q", buffer[:count])
	}
}

func TestBoundedCommandOutput(t *testing.T) {
	output := &boundedCommandOutput{limit: 5}
	for _, value := range []string{"abc", "def", "ghi"} {
		if count, err := output.Write([]byte(value)); err != nil || count != len(value) {
			t.Fatalf("unexpected write result %d, %v", count, err)
		}
	}
	content, exceeded := output.result()
	if content != "abcde" || !exceeded {
		t.Fatalf("unexpected bounded output %q exceeded=%v", content, exceeded)
	}
}

func TestChildCommandEnvironmentDropsSystemdActivationVariables(t *testing.T) {
	input := []string{
		"PATH=/usr/bin", "NOTIFY_SOCKET=/run/systemd/notify", "WATCHDOG_USEC=1000000",
		"WATCHDOG_PID=123", "LISTEN_FDS=1", "LISTEN_FDNAMES=http", "LISTEN_PID=123", "LANG=C",
	}
	got := childCommandEnvironment(input)
	if len(got) != 2 || got[0] != "PATH=/usr/bin" || got[1] != "LANG=C" {
		t.Fatalf("unexpected child environment: %#v", got)
	}
}

func TestWireGuardInputValidation(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if !validWireGuardPublicKey(key) {
		t.Fatal("expected a 32-byte public key to be valid")
	}
	if validWireGuardPublicKey("not-a-key") {
		t.Fatal("expected malformed public key rejection")
	}
	for _, value := range []string{"wg-porthub", "wg_1", "eth0"} {
		if !validInterfaceName(value) {
			t.Fatalf("expected valid interface %q", value)
		}
	}
	for _, value := range []string{"", "wg/porthub", "interface-name-is-too-long"} {
		if validInterfaceName(value) {
			t.Fatalf("expected invalid interface %q", value)
		}
	}
}

func TestValidatedPathRejectsEscapeAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "candidate.nft")
	if err := os.WriteFile(path, []byte("table inet porthub_core {}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := validatedPath(dir, path); err != nil {
		t.Fatal(err)
	}
	if _, err := validatedPath(dir, filepath.Join(dir, "..", "escape.nft")); err == nil {
		t.Fatal("expected path escape rejection")
	}
	link := filepath.Join(dir, "link.nft")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := validatedPath(dir, link); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestRelayRulesOverlap(t *testing.T) {
	base := relayRule{ID: 1, Name: "a", ListenFamily: "ipv4", ListenAddress: "192.0.2.10",
		ListenPortStart: 8000, ListenPortEnd: 8010, Protocol: "tcp",
		TargetHost: "10.0.0.1", TargetPortStart: 8000, TargetPortEnd: 8010}
	cases := []struct {
		name    string
		other   relayRule
		overlap bool
	}{
		{"identical range", relayRule{ID: 2, ListenFamily: "ipv4", ListenAddress: "0.0.0.0", ListenPortStart: 8000, ListenPortEnd: 8010, Protocol: "tcp"}, true},
		{"partial overlap", relayRule{ID: 3, ListenFamily: "ipv4", ListenAddress: "0.0.0.0", ListenPortStart: 8005, ListenPortEnd: 8015, Protocol: "tcp"}, true},
		{"adjacent no overlap", relayRule{ID: 4, ListenFamily: "ipv4", ListenAddress: "0.0.0.0", ListenPortStart: 8011, ListenPortEnd: 8020, Protocol: "tcp"}, false},
		{"both overlaps tcp", relayRule{ID: 5, ListenFamily: "ipv4", ListenAddress: "0.0.0.0", ListenPortStart: 8000, ListenPortEnd: 8002, Protocol: "both"}, true},
		{"udp vs tcp no overlap", relayRule{ID: 6, ListenFamily: "ipv4", ListenAddress: "0.0.0.0", ListenPortStart: 8000, ListenPortEnd: 8002, Protocol: "udp"}, false},
		{"different family", relayRule{ID: 7, ListenFamily: "ipv6", ListenAddress: "::", ListenPortStart: 8000, ListenPortEnd: 8002, Protocol: "tcp"}, false},
		{"wildcard vs specific", relayRule{ID: 8, ListenFamily: "ipv4", ListenAddress: "192.0.2.10", ListenPortStart: 8000, ListenPortEnd: 8002, Protocol: "tcp"}, true},
		{"specific vs specific different", relayRule{ID: 9, ListenFamily: "ipv4", ListenAddress: "192.0.2.11", ListenPortStart: 8000, ListenPortEnd: 8002, Protocol: "tcp"}, false},
		{"specific vs same specific", relayRule{ID: 10, ListenFamily: "ipv4", ListenAddress: "192.0.2.10", ListenPortStart: 8000, ListenPortEnd: 8002, Protocol: "tcp"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := relayRulesOverlap(base, tc.other); got != tc.overlap {
				t.Fatalf("relayRulesOverlap = %v, want %v", got, tc.overlap)
			}
		})
	}
}

func TestValidateNFTStructuredChainWhitelist(t *testing.T) {
	// Chains PortHub emits are accepted.
	valid := "flush table inet porthub_core\ntable inet porthub_core {\n" +
		" chain forward { type filter hook forward priority 0; policy accept; }\n" +
		" chain prerouting { type nat hook prerouting priority -100; }\n" +
		" chain postrouting { type nat hook postrouting priority 100; }\n" +
		"}\n"
	if err := validateNFT(valid, "porthub_core"); err != nil {
		t.Fatalf("valid whitelisted chains rejected: %v", err)
	}
	// Foreign chain names must be rejected even inside the owned table.
	foreign := []string{
		"table inet porthub_core {\n chain evil { type filter hook forward priority 0; policy accept; }\n}\n",
		"table inet porthub_core {\n chain input { type filter hook input priority 0; policy accept; }\n}\n",
		"table inet porthub_core {\n chain prerouting { type nat hook prerouting priority -100; }\n chain custom { type filter hook forward priority 0; policy accept; }\n}\n",
	}
	for _, payload := range foreign {
		if err := validateNFT(payload, "porthub_core"); err == nil {
			t.Fatalf("expected rejection for forbidden chain payload:\n%s", payload)
		}
	}
	// goto/jump into a foreign table must be rejected.
	jump := "table inet porthub_core {\n chain forward { type filter hook forward priority 0; policy accept; }\n" +
		" chain postrouting { type nat hook postrouting priority 100; }\n" +
		"}\nadd rule inet filter forward jump porthub_core\n"
	if err := validateNFT(jump, "porthub_core"); err == nil {
		t.Fatal("expected rejection for foreign table reference")
	}
}
