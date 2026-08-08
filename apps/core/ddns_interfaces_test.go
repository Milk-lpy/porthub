package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// listNetworkInterfaces must return at least one non-loopback interface
// (the test machine always has one, e.g. eth0/ens*/lo excluded).
func TestListNetworkInterfaces(t *testing.T) {
	ifaces := listNetworkInterfaces()
	if len(ifaces) == 0 {
		t.Fatal("expected at least one non-loopback interface")
	}
	found := false
	for _, iface := range ifaces {
		if iface.Name == "" {
			t.Fatal("interface name must not be empty")
		}
		if len(iface.IPv4) > 0 || len(iface.IPv6) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected at least one interface with an address")
	}
}

func TestSelectDDNSInterfaceIPv6SkipsLinkLocalByDefault(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(64, 128)},
	}
	selected := selectDDNSInterfaceIP(addrs, "AAAA", nil)
	if selected == nil || selected.String() != "2001:db8::10" {
		t.Fatalf("selected %v, want public IPv6", selected)
	}
}

func TestSelectDDNSInterfaceRejectsPrivateAddressByDefault(t *testing.T) {
	addrs := []net.Addr{&net.IPNet{IP: net.ParseIP("10.20.30.12"), Mask: net.CIDRMask(24, 32)}}
	if selected := selectDDNSInterfaceIP(addrs, "A", nil); selected != nil {
		t.Fatalf("selected private address %v", selected)
	}
}

// TestDDNSInterfacesHandler verifies the JSON shape served to the picker.
func TestDDNSInterfacesHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/ddns/interfaces", nil)
	rec := httptest.NewRecorder()
	ddnsInterfacesHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var out []NetInterfaceInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty interface list")
	}
	// every entry must be well-formed
	for _, iface := range out {
		if iface.Name == "" {
			t.Fatal("interface without name in JSON response")
		}
	}
}
