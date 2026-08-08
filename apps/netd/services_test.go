package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseManagedServicesUsesCompiledAllowlist(t *testing.T) {
	services, err := parseManagedServices("qx-lan-socks, qx-lan-config-http,dst-wireguard,dst-wireguard-health,dst-wireguard-register,prefer-real-ipv6-gateway,qx-lan-socks")
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 6 || !services["qx-lan-socks"] || !services["qx-lan-config-http"] || !services["dst-wireguard"] || !services["prefer-real-ipv6-gateway"] {
		t.Fatalf("unexpected services: %#v", services)
	}
	for _, value := range []string{"ssh", "qx-lan-socks;reboot", "qx-lan-socks.service"} {
		if _, err := parseManagedServices(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func TestManagedServiceActionRejectsUnlistedInputs(t *testing.T) {
	cfg := serverConfig{managedServices: map[string]bool{"qx-lan-socks": true, "prefer-real-ipv6-gateway": true}}
	cases := []struct {
		body string
		code int
	}{
		{`{"service":"ssh","action":"start"}`, http.StatusForbidden},
		{`{"service":"qx-lan-socks","action":"reload; reboot"}`, http.StatusBadRequest},
		{`{"service":"prefer-real-ipv6-gateway","action":"stop"}`, http.StatusBadRequest},
		{`{"service":"qx-lan-socks","action":"start","extra":"value"}`, http.StatusBadRequest},
	}
	for _, test := range cases {
		request := httptest.NewRequest(http.MethodPost, "/v1/services/action", strings.NewReader(test.body))
		response := httptest.NewRecorder()
		managedServiceAction(response, request, cfg)
		if response.Code != test.code {
			t.Fatalf("body %s: got %d, want %d", test.body, response.Code, test.code)
		}
	}
}

func TestParseManagedWireGuardStateFields(t *testing.T) {
	addresses := parseInterfaceAddresses(strings.Join([]string{
		"4: wg-dst    inet 10.254.0.1/24 scope global wg-dst",
		"4: wg-dst    inet6 fe80::1/64 scope link",
	}, "\n"))
	if len(addresses) != 2 || addresses[0] != "10.254.0.1/24" || addresses[1] != "fe80::1/64" {
		t.Fatalf("unexpected addresses: %#v", addresses)
	}
	latest := parseLatestHandshake("peer-a 1700000000\npeer-b 1700000300\npeer-c 0\n")
	if latest != 1700000300 {
		t.Fatalf("unexpected latest handshake %d", latest)
	}
	rx, tx := parseWireGuardTransfer("peer-a 100 200\npeer-b 300 400\n")
	if rx != 400 || tx != 600 {
		t.Fatalf("unexpected transfer rx=%d tx=%d", rx, tx)
	}
}

func TestParseSystemctlShowAndListeners(t *testing.T) {
	state := parseSystemctlShow("qx-lan-socks", strings.Join([]string{
		"Description=QX LAN SOCKS5",
		"ActiveState=active",
		"SubState=running",
		"UnitFileState=enabled",
		"MainPID=14164",
		"ExecMainStartTimestamp=Sat 2026-08-01 10:20:30 CST",
	}, "\n"))
	if state.Name != "qx-lan-socks" || state.MainPID != 14164 || state.ActiveState != "active" || state.UnitFileState != "enabled" {
		t.Fatalf("unexpected service state: %#v", state)
	}

	listeners := parseServiceListeners(strings.Join([]string{
		`tcp LISTEN 0 128 192.0.2.12:10888 0.0.0.0:*`,
		`udp UNCONN 0 0 *:10888 *:*`,
		`tcp LISTEN 0 128 127.0.0.1:9999 0.0.0.0:*`,
	}, "\n"), "qx-lan-socks")
	if len(listeners) != 2 {
		t.Fatalf("unexpected listeners: %#v", listeners)
	}
	if listeners[0].Protocol != "tcp" || listeners[0].Address != "192.0.2.12" || listeners[0].Port != 10888 {
		t.Fatalf("unexpected tcp listener: %#v", listeners[0])
	}
	if listeners[1].Protocol != "udp" || listeners[1].Address != "全部地址" || listeners[1].Port != 10888 {
		t.Fatalf("unexpected udp listener: %#v", listeners[1])
	}
}

func TestParseListenerEndpoint(t *testing.T) {
	cases := []struct {
		value   string
		address string
		port    int
	}{
		{"[::]:10889", "::", 10889},
		{"0.0.0.0:8080", "0.0.0.0", 8080},
		{"*:53", "全部地址", 53},
	}
	for _, test := range cases {
		address, port, ok := parseListenerEndpoint(test.value)
		if !ok || address != test.address || port != test.port {
			t.Fatalf("%q parsed as %q:%d ok=%t", test.value, address, port, ok)
		}
	}
	for _, invalid := range []string{"missing-port", "127.0.0.1:0", "127.0.0.1:70000"} {
		if _, _, ok := parseListenerEndpoint(invalid); ok {
			t.Fatalf("expected %q to be rejected", invalid)
		}
	}
}
