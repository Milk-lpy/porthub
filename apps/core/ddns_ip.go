package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Public IP discovery for PortHub-managed DDNS records.
//
// ip_source=public_api  -> fetch candidate public IPs from a URL list, extract
//                          with a regex (IPv4/IPv6 aware), cache per URL.
// ip_source=net_interface -> read the IP of a local network interface,
//                            optionally filtered by a custom regex.

const (
	defaultIPv4ProbeURL = "https://api.ipify.org"
	defaultIPv6ProbeURL = "https://api6.ipify.org"
	ipFetchTimeout      = 10 * time.Second
	ipFetchMaxBody      = 1 << 16
	ipCacheTTL          = 15 * time.Minute
)

// Ipv4Reg extracts an IPv4 address from a provider response.
const Ipv4Reg = `((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])`

// Ipv6Reg extracts an IPv6 address from a provider response.
const Ipv6Reg = `((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))`

var (
	ipv4ProbePattern = regexp.MustCompile(Ipv4Reg)
	ipv6ProbePattern = regexp.MustCompile(Ipv6Reg)

	// ipProbeCache caches the extracted IP per probe URL.
	ipProbeCache sync.Map // url -> cachedIPEntry

	// cgnat4 is the RFC 6598 Carrier-Grade NAT block (100.64.0.0/10).
	// It covers Alibaba Cloud's metadata endpoint (100.100.100.200) and other
	// shared address space that must never be an outbound destination.
	cgnat4 = &net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)}
)

type cachedIPEntry struct {
	ip        string
	fetchedAt time.Time
}

// defaultProbeURLs returns default public IP probe endpoints for a record type.
func defaultProbeURLs(recordType string) []string {
	if recordType == "AAAA" {
		return []string{defaultIPv6ProbeURL, "https://6.ipw.cn", "https://v6.ident.me"}
	}
	return []string{defaultIPv4ProbeURL, "https://4.ipw.cn", "https://v4.ident.me"}
}

// resolvePublicAPIValue fetches the public IP from the record's URL list.
// It falls back to default probe endpoints when the record has no URLs.
func resolvePublicAPIValue(record ddnsRecordItem) (string, error) {
	urls := record.IPURLs
	if len(urls) == 0 {
		urls = defaultProbeURLs(record.RecordType)
	}
	pattern := ipv4ProbePattern
	if record.RecordType == "AAAA" {
		pattern = ipv6ProbePattern
	}
	var lastErr error
	for _, rawURL := range urls {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" {
			continue
		}
		ip, err := probeIPFromURL(rawURL, pattern, record.RecordType)
		if err != nil {
			lastErr = err
			continue
		}
		return ip, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no IP probe URL configured")
	}
	return "", lastErr
}

// allowLocalProbeHosts is enabled by tests that spin up loopback HTTP
// servers; production always blocks loopback/private/metadata targets.
var allowLocalProbeHosts = false

// safeOutboundClient returns an http.Client hardened against SSRF for
// administrator-supplied URLs: redirects are refused and dialing loopback,
// private, link-local and cloud-metadata addresses is blocked.
func safeOutboundClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // never follow redirects
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					host, port = addr, ""
				}
				// Resolve once and dial the VERIFIED IP. Dialing by IP
				// instead of the hostname closes the DNS-rebinding
				// window (an attacker-controlled name could resolve to
				// a public IP for the check and an internal IP for the
				// dial). The Host/SNI header still carries the original
				// hostname because http.Transport derives it from the
				// request URL, not from the dial address.
				ip, err := resolveVerifiedOutboundIP(host)
				if err != nil {
					return nil, err
				}
				dialAddr := ip
				if port != "" {
					dialAddr = net.JoinHostPort(ip, port)
				}
				var dialer net.Dialer
				return dialer.DialContext(ctx, network, dialAddr)
			},
		},
	}
}

// resolveVerifiedOutboundIP resolves a hostname exactly once and returns the
// first allowed IP address (or the IP itself for a literal address). Callers
// must dial THIS IP, never re-resolve the hostname, to avoid DNS rebinding.
func resolveVerifiedOutboundIP(host string) (string, error) {
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		if blockedOutboundIP(ip) {
			if allowLocalProbeHosts && ip.IsLoopback() {
				return ip.String(), nil
			}
			return "", fmt.Errorf("outbound address %s blocked by SSRF protection", host)
		}
		return ip.String(), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("outbound host %s unresolvable", host)
	}
	for _, candidate := range ips {
		if blockedOutboundIP(candidate) {
			if allowLocalProbeHosts && candidate.IsLoopback() {
				return candidate.String(), nil
			}
			continue
		}
		return candidate.String(), nil
	}
	return "", fmt.Errorf("outbound host %s has no allowed address", host)
}

func blockedOutboundIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// Cloud metadata endpoints (169.254.169.254 / fe80::a9fe:a9fe).
	if ip.To4() != nil && ip.To4().Equal(net.IPv4(169, 254, 169, 254)) {
		return true
	}
	// RFC 6598 CGNAT (includes Alibaba Cloud metadata 100.100.100.200)
	if ip4 := ip.To4(); ip4 != nil && cgnat4.Contains(ip4) {
		return true
	}
	return false
}

func probeIPFromURL(rawURL string, pattern *regexp.Regexp, recordType string) (string, error) {
	if cached, ok := ipProbeCache.Load(rawURL); ok {
		entry := cached.(cachedIPEntry)
		if time.Since(entry.fetchedAt) < ipCacheTTL && entry.ip != "" {
			return entry.ip, nil
		}
	}
	client := safeOutboundClient(ipFetchTimeout)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "PortHub-DDNS/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, ipFetchMaxBody))
	if err != nil {
		return "", err
	}
	match := pattern.FindString(string(body))
	if match == "" {
		return "", fmt.Errorf("probe %s returned no %s address", rawURL, recordType)
	}
	ip := net.ParseIP(match)
	if ip == nil {
		return "", fmt.Errorf("probe %s returned invalid IP %q", rawURL, match)
	}
	if recordType == "AAAA" && ip.To4() != nil {
		return "", fmt.Errorf("probe %s returned IPv4 for AAAA record", rawURL)
	}
	clean := ip.String()
	ipProbeCache.Store(rawURL, cachedIPEntry{ip: clean, fetchedAt: time.Now()})
	return clean, nil
}

// resolveNetInterfaceValue reads the IP from a local network interface,
// optionally filtered by a custom regex.
func resolveNetInterfaceValue(record ddnsRecordItem) (string, error) {
	ifaceName := strings.TrimSpace(record.NetInterface)
	if ifaceName == "" {
		return "", errors.New("net_interface ip_source requires net_interface name")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("interface %s not found", ifaceName)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	var pattern *regexp.Regexp
	if strings.TrimSpace(record.IPRegex) != "" {
		pattern, err = regexp.Compile(record.IPRegex)
		if err != nil {
			return "", errors.New("invalid ip_regex")
		}
	}
	if ip := selectDDNSInterfaceIP(addrs, record.RecordType, pattern); ip != nil {
		return ip.String(), nil
	}
	return "", fmt.Errorf("interface %s has no matching %s address", ifaceName, record.RecordType)
}

func selectDDNSInterfaceIP(addrs []net.Addr, recordType string, pattern *regexp.Regexp) net.IP {
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		if ip == nil {
			continue
		}
		if recordType == "AAAA" {
			if ip.To4() != nil {
				continue
			}
		} else {
			if ip.To4() == nil {
				continue
			}
		}
		// With no custom selector, DDNS must never publish a loopback,
		// link-local or private interface address. This also makes selection
		// deterministic when the kernel lists fe80:: before the public IPv6.
		if pattern == nil && (!ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			continue
		}
		if pattern != nil && !pattern.MatchString(ip.String()) {
			continue
		}
		return ip
	}
	return nil
}

// resolveCorePublicValue returns the Core's own outbound public IP, discovered
// from the default probe endpoints. Unlike edge_public this does not depend on
// the Edge reporting its address.
func resolveCorePublicValue(record ddnsRecordItem) (string, error) {
	return resolvePublicAPIValue(record)
}

// NetInterfaceInfo describes one local network interface with its addresses,
// used by the interactive "本机网卡" IP source picker in the frontend.
type NetInterfaceInfo struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac,omitempty"`
	Up   bool     `json:"up"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

// listNetworkInterfaces enumerates all local network interfaces with their
// current IPv4 and IPv6 addresses (loopback excluded).
func listNetworkInterfaces() []NetInterfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]NetInterfaceInfo, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		info := NetInterfaceInfo{
			Name: iface.Name,
			MAC:  iface.HardwareAddr.String(),
			Up:   iface.Flags&net.FlagUp != 0,
			// initialize to empty slices so JSON is [] instead of null — the
			// frontend spreads these arrays and null would crash the render
			IPv4: []string{},
			IPv6: []string{},
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				info.IPv4 = append(info.IPv4, v4.String())
			} else {
				// keep link-local IPv6 (fe80::) too — users may target them
				info.IPv6 = append(info.IPv6, ip.String())
			}
		}
		out = append(out, info)
	}
	return out
}

// ddnsInterfacesHandler serves the local interface list for the DDNS
// "本机网卡" interactive picker (GET /api/ddns/interfaces).
func ddnsInterfacesHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, listNetworkInterfaces())
}
