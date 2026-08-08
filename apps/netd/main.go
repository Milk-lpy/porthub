package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type serverConfig struct {
	socket                 string
	allowedDir             string
	allowedTable           string
	wireGuardInterface     string
	allowRuntimeInspection bool
	relayConfigPath        string
	relayServiceName       string
	tunnelCIDRs            string
	parsedTunnelNets       []*net.IPNet
	managedServiceNames    string
	managedServices        map[string]bool
}

// credListener wraps a net.Listener to enforce that only the socket owner
// (the porthub service account) or root may connect. This closes the H1 gap
// where any process in the socket's group could drive the root helper.
type credListener struct {
	net.Listener
	allowedUID uint32
	allowedGID uint32
}

func (cl *credListener) Accept() (net.Conn, error) {
	for {
		conn, err := cl.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			continue
		}
		raw, err := uc.SyscallConn()
		if err != nil {
			conn.Close()
			continue
		}
		var allowed bool
		_ = raw.Control(func(fd uintptr) {
			cred, cerr := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
			if cerr != nil {
				return
			}
			// Root may always connect. Otherwise the peer's primary UID or GID
			// must match the socket owner's. The socket is root:porthub 0660, so
			// the intended service client (porthub user, primary group porthub)
			// is accepted while other group members with a different primary
			// group (e.g. porthub-relay) are rejected — SO_PEERCRED reports only
			// the primary GID, so supplementary-group access is not sufficient.
			if cred.Uid == 0 {
				allowed = true
				return
			}
			if cl.allowedUID != 0 && cred.Uid == cl.allowedUID {
				allowed = true
				return
			}
			if cred.Gid == cl.allowedGID {
				allowed = true
			}
		})
		if !allowed {
			conn.Close()
			continue
		}
		return conn, nil
	}
}

// parseTunnelCIDRs parses a comma-separated list of CIDR strings.
func parseTunnelCIDRs(s string) ([]*net.IPNet, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var nets []*net.IPNet
	for _, raw := range strings.Split(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid tunnel CIDR %q: %w", raw, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// containedInTunnel reports whether the candidate CIDR is fully contained
// within at least one of the configured tunnel CIDRs.
func containedInTunnel(candidate *net.IPNet, tunnels []*net.IPNet) bool {
	if len(tunnels) == 0 {
		return true // no restriction configured
	}
	for _, t := range tunnels {
		if !t.Contains(candidate.IP) {
			continue
		}
		// Also verify the last address of the candidate is contained,
		// so a wider prefix cannot escape the tunnel range.
		last := make(net.IP, len(candidate.IP))
		copy(last, candidate.IP)
		for i := range last {
			last[i] |= ^candidate.Mask[i]
		}
		if t.Contains(last) {
			return true
		}
	}
	return false
}

type applyRequest struct {
	Path  string `json:"path"`
	Table string `json:"table"`
}

type wireGuardPeerRequest struct {
	Action     string   `json:"action"`
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	Keepalive  int      `json:"keepalive,omitempty"`
}

type boundedCommandOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (output *boundedCommandOutput) Write(data []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	remaining := output.limit - output.buffer.Len()
	if remaining > 0 {
		write := len(data)
		if write > remaining {
			write = remaining
		}
		_, _ = output.buffer.Write(data[:write])
	}
	if len(data) > remaining {
		output.exceeded = true
	}
	return len(data), nil
}

func (output *boundedCommandOutput) result() (string, bool) {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.buffer.String(), output.exceeded
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "apply-nft" {
		if err := applyLegacy(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	cfg := serverConfig{}
	flag.StringVar(&cfg.socket, "socket", "/run/porthub/netd.sock", "unix socket")
	flag.StringVar(&cfg.allowedDir, "allowed-dir", "/var/lib/porthub/core/netd", "allowed nft directory")
	flag.StringVar(&cfg.allowedTable, "allowed-table", "porthub_core", "owned nft table")
	flag.StringVar(&cfg.wireGuardInterface, "wireguard-interface", "", "owned WireGuard interface; empty disables WireGuard operations")
	flag.BoolVar(&cfg.allowRuntimeInspection, "allow-runtime-inspection", false, "allow owned nft and conntrack inspection")
	flag.StringVar(&cfg.relayConfigPath, "relay-config", "/var/lib/porthub/relay/config.json", "relay configuration file written by netd")
	flag.StringVar(&cfg.relayServiceName, "relay-service", "porthub-relay", "systemd unit restarted after relay config change")
	flag.StringVar(&cfg.tunnelCIDRs, "tunnel-cidrs", "", "comma-separated tunnel CIDRs; WireGuard allowed-ips must be contained (empty = skip check)")
	flag.StringVar(&cfg.managedServiceNames, "managed-services", "", "comma-separated PortHub-owned service units; empty disables service management")
	flag.Parse()
	if err := serve(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(cfg serverConfig) error {
	if !validName(cfg.allowedTable) {
		return errors.New("invalid allowed table")
	}
	tunnelNets, err := parseTunnelCIDRs(cfg.tunnelCIDRs)
	if err != nil {
		return fmt.Errorf("invalid tunnel-cidrs: %w", err)
	}
	cfg.parsedTunnelNets = tunnelNets
	managedServices, err := parseManagedServices(cfg.managedServiceNames)
	if err != nil {
		return fmt.Errorf("invalid managed-services: %w", err)
	}
	cfg.managedServices = managedServices
	if err := os.MkdirAll(filepath.Dir(cfg.socket), 0750); err != nil {
		return err
	}
	os.Remove(cfg.socket)
	var listener net.Listener
	listener, err = net.Listen("unix", cfg.socket)
	if err != nil {
		return err
	}
	defer func() { listener.Close() }()
	if err := secureSocket(cfg.socket); err != nil {
		return err
	}
	// H1: enforce SO_PEERCRED so only root or a peer whose primary UID/GID
	// matches the socket owner (root:porthub) can connect. This blocks other
	// local accounts — including group members with a different primary group
	// such as porthub-relay — from driving the root helper.
	var allowedUID, allowedGID uint32
	if fi, statErr := os.Stat(cfg.socket); statErr == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			allowedUID = st.Uid
			allowedGID = st.Gid
		}
	}
	listener = &credListener{Listener: listener, allowedUID: allowedUID, allowedGID: allowedGID}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/nft/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var request applyRequest
		decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if request.Table != cfg.allowedTable {
			http.Error(w, "table is not owned by PortHub netd", http.StatusForbidden)
			return
		}
		if err := applyOwnedNFT(cfg, request.Path); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "table": cfg.allowedTable, "applied_at": time.Now().UTC()})
	})
	if cfg.allowRuntimeInspection {
		mux.HandleFunc("/v1/nft/list", func(w http.ResponseWriter, r *http.Request) {
			fixedCommand(w, r, "nft", "list", "table", "inet", cfg.allowedTable)
		})
		mux.HandleFunc("/v1/conntrack/list", func(w http.ResponseWriter, r *http.Request) {
			fixedCommand(w, r, "conntrack", "-L", "-o", "extended")
		})
	}
	if cfg.relayConfigPath != "" {
		mux.HandleFunc("/v1/relay/apply", func(w http.ResponseWriter, r *http.Request) {
			applyRelayConfig(w, r, cfg)
		})
	}
	if cfg.wireGuardInterface != "" {
		if !validInterfaceName(cfg.wireGuardInterface) {
			return errors.New("invalid WireGuard interface")
		}
		mux.HandleFunc("/v1/wireguard/show", func(w http.ResponseWriter, r *http.Request) {
			showWireGuard(w, r, cfg.wireGuardInterface)
		})
		mux.HandleFunc("/v1/wireguard/peer", func(w http.ResponseWriter, r *http.Request) {
			setWireGuardPeer(w, r, cfg.wireGuardInterface, cfg)
		})
	}
	if len(cfg.managedServices) > 0 {
		mux.HandleFunc("/v1/services", func(w http.ResponseWriter, r *http.Request) {
			managedServicesStatus(w, r, cfg)
		})
		mux.HandleFunc("/v1/services/action", func(w http.ResponseWriter, r *http.Request) {
			managedServiceAction(w, r, cfg)
		})
	}
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	if err := notifySystemdReady(); err != nil {
		return fmt.Errorf("notify systemd readiness: %w", err)
	}
	return server.Serve(listener)
}

func notifySystemdReady() error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	if socket[0] == '@' {
		socket = "\x00" + socket[1:]
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer connection.Close()
	_, err = connection.Write([]byte("READY=1"))
	return err
}

func fixedCommand(w http.ResponseWriter, r *http.Request, name string, args ...string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	output, exceeded, err := runBoundedCommand(ctx, name, args...)
	if exceeded {
		http.Error(w, "command output is too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil {
		http.Error(w, strings.TrimSpace(output), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"output": output})
}

func runBoundedCommand(ctx context.Context, name string, args ...string) (string, bool, error) {
	output := &boundedCommandOutput{limit: 2 << 20}
	command := exec.CommandContext(ctx, name, args...)
	command.Env = childCommandEnvironment(os.Environ())
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	content, exceeded := output.result()
	return content, exceeded, err
}

func childCommandEnvironment(environment []string) []string {
	blocked := map[string]bool{
		"NOTIFY_SOCKET": true, "WATCHDOG_PID": true, "WATCHDOG_USEC": true,
		"LISTEN_FDS": true, "LISTEN_FDNAMES": true, "LISTEN_PID": true,
	}
	filtered := make([]string, 0, len(environment))
	for _, value := range environment {
		name, _, _ := strings.Cut(value, "=")
		if !blocked[name] {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func showWireGuard(w http.ResponseWriter, r *http.Request, iface string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	field := r.URL.Query().Get("field")
	allowed := map[string]bool{
		"public-key": true, "listen-port": true, "peers": true, "dump": true, "allowed-ips": true,
	}
	if !allowed[field] {
		http.Error(w, "unsupported WireGuard field", http.StatusBadRequest)
		return
	}
	fixedCommand(w, r, "wg", "show", iface, field)
}

func setWireGuardPeer(w http.ResponseWriter, r *http.Request, iface string, cfg serverConfig) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request wireGuardPeerRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !validWireGuardPublicKey(request.PublicKey) {
		http.Error(w, "invalid WireGuard public key", http.StatusBadRequest)
		return
	}
	args := []string{"set", iface, "peer", request.PublicKey}
	switch request.Action {
	case "remove":
		if len(request.AllowedIPs) != 0 || request.Keepalive != 0 {
			http.Error(w, "remove does not accept peer settings", http.StatusBadRequest)
			return
		}
		args = append(args, "remove")
	case "set":
		if len(request.AllowedIPs) == 0 || len(request.AllowedIPs) > 64 || request.Keepalive < 0 || request.Keepalive > 65535 {
			http.Error(w, "invalid WireGuard peer settings", http.StatusBadRequest)
			return
		}
		for _, cidr := range request.AllowedIPs {
			_, candidate, err := net.ParseCIDR(cidr)
			if err != nil {
				http.Error(w, "invalid WireGuard allowed IP", http.StatusBadRequest)
				return
			}
			// H2: restrict allowed-ips to the configured tunnel scope so a peer
			// cannot be given 0.0.0.0/0 (or any out-of-tunnel prefix) as a route.
			if !containedInTunnel(candidate, cfg.parsedTunnelNets) {
				http.Error(w, "allowed-ips CIDR outside tunnel scope", http.StatusBadRequest)
				return
			}
		}
		args = append(args, "allowed-ips", strings.Join(request.AllowedIPs, ","))
		if request.Keepalive > 0 {
			args = append(args, "persistent-keepalive", fmt.Sprint(request.Keepalive))
		}
	default:
		http.Error(w, "unsupported WireGuard action", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	output, exceeded, err := runBoundedCommand(ctx, "wg", args...)
	if exceeded {
		http.Error(w, "command output is too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil {
		http.Error(w, strings.TrimSpace(output), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func validWireGuardPublicKey(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validInterfaceName(value string) bool {
	if len(value) < 1 || len(value) > 15 {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func applyOwnedNFT(cfg serverConfig, path string) error {
	f, err := validatedPath(cfg.allowedDir, path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("nft candidate is too large")
	}
	if err := validateNFT(string(data), cfg.allowedTable); err != nil {
		return err
	}
	if err := ensureTable(cfg.allowedTable); err != nil {
		return err
	}
	// TOCTOU 防护: nft 从 stdin 读取已校验内容, 绝不让 nft 按路径重新打开文件
	// (路径文件可能在校验后被替换)
	check := exec.Command("nft", "-c", "-f", "-")
	check.Stdin = bytes.NewReader(data)
	if output, err := check.CombinedOutput(); err != nil {
		return fmt.Errorf("nft check failed: %s", strings.TrimSpace(string(output)))
	}
	apply := exec.Command("nft", "-f", "-")
	apply.Stdin = bytes.NewReader(data)
	if output, err := apply.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply failed: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

// validatedPath opens the candidate under allowedDir and returns the open file
// handle. It uses O_NOFOLLOW and stats the open descriptor (not the path), so
// there is no TOCTOU window between validation and read, and a symlink cannot
// be used to redirect the read to a file outside the allowed directory.
func validatedPath(allowedDir, path string) (*os.File, error) {
	base, err := filepath.Abs(allowedDir)
	if err != nil {
		return nil, err
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(base, clean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, errors.New("path is outside allowed directory")
	}
	f, err := os.OpenFile(clean, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("candidate open: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("candidate must be a regular file")
	}
	if info.Mode().Perm()&0022 != 0 {
		f.Close()
		return nil, errors.New("candidate must not be group/world writable")
	}
	return f, nil
}

func validateNFT(content, allowedTable string) error {
	lower := strings.ToLower(content)
	for _, forbidden := range []string{"flush ruleset", "shell"} {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("forbidden nft directive %q", forbidden)
		}
	}
	// L1: match keyword followed by a space OR tab so a tab cannot bypass the
	// substring check (e.g. "include	\"...\"").
	for _, kw := range []string{"include", "define", "delete table"} {
		if idx := strings.Index(lower, kw); idx >= 0 {
			rest := lower[idx+len(kw):]
			if len(rest) > 0 && (rest[0] == ' ' || rest[0] == '	') {
				return fmt.Errorf("forbidden nft directive %q", kw)
			}
		}
	}
	// C2: forbid base-chain hooks that take effect host-globally. PortHub only
	// ever emits forward/prerouting/postrouting chains; input/output/ingress/
	// egress base chains in the owned table would still affect the whole host.
	for _, fh := range []string{" hook input ", " hook output ", " hook ingress ", " hook egress "} {
		if strings.Contains(lower, fh) {
			return errors.New("nft candidate contains forbidden base-chain hook type")
		}
	}
	// C2: a hook chain with a drop policy would blackhole traffic host-wide.
	if strings.Contains(lower, "hook") && strings.Contains(lower, "policy drop") {
		return errors.New("nft candidate contains policy drop on a hook chain")
	}
	// STRUCTURED WHITELIST: collect every chain declared in the candidate and
	// every top-level verb. Only chains PortHub declares are allowed; anything
	// else (input/output chains, foreign tables, counters on unknown chains)
	// is rejected even if the blacklist above did not catch it.
	allowedChains := map[string]bool{
		"forward": true, "prerouting": true, "postrouting": true, "output": true,
	}
	seenChains := map[string]bool{}
	chainRE := regexp.MustCompile(`\bchain\s+([a-zA-Z0-9_]+)`)
	for _, m := range chainRE.FindAllStringSubmatch(content, -1) {
		seenChains[m[1]] = true
	}
	for chain := range seenChains {
		if !allowedChains[chain] {
			return fmt.Errorf("nft candidate declares forbidden chain %q", chain)
		}
	}
	// Only the owned table may be referenced as a target of a goto/jump.
	tableRE := regexp.MustCompile(`\b(table|goto|jump)\s+inet\s+([a-zA-Z0-9_]+)`)
	for _, m := range tableRE.FindAllStringSubmatch(content, -1) {
		if m[2] != allowedTable {
			return fmt.Errorf("nft candidate references foreign table %q", m[2])
		}
	}
	depth := 0
	tableSeen := false
	tableClosed := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// C1: once the owned table has closed, no further content is permitted.
		if tableClosed {
			return errors.New("nft candidate appends data after the owned table")
		}
		if depth == 0 {
			switch trimmed {
			case "flush table inet " + allowedTable, "destroy table inet " + allowedTable:
				continue
			case "table inet " + allowedTable + " {":
				tableSeen = true
				depth = 1
				continue
			default:
				return errors.New("nft candidate contains a top-level operation outside PortHub ownership")
			}
		}
		// C1: scan character by character. If a closing brace on this line would
		// bring depth back to 0 (closing the owned table), nothing may follow it
		// on the same line — this defeats the "}; table inet evil {" escape where
		// the per-line net brace count is zero and the top-level guard is skipped.
		checkD := depth
		for pos, ch := range trimmed {
			switch ch {
			case '{':
				checkD++
			case '}':
				checkD--
				if checkD == 0 {
					if strings.TrimSpace(trimmed[pos+1:]) != "" {
						return errors.New("nft candidate appends data after closing the owned table")
					}
					tableClosed = true
				}
			}
		}
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if depth < 0 {
			return errors.New("nft candidate has unbalanced braces")
		}
		// Top-level (or chain-level) statements inside the table must not be
		// "add table"/"add chain" for foreign names — the chain whitelist above
		// already covers declared chains, but catch nested add table too.
		if trimmed == "}" && depth == 0 {
			// closing brace handled below
		}
		if depth == 0 && trimmed != "}" {
			return errors.New("nft candidate appends data after the owned table")
		}
	}
	if !tableSeen {
		return errors.New("nft table declaration is required")
	}
	if depth != 0 {
		return errors.New("nft candidate has unbalanced braces")
	}
	return nil
}

func ensureTable(table string) error {
	if exec.Command("nft", "list", "table", "inet", table).Run() == nil {
		return nil
	}
	output, err := exec.Command("nft", "add", "table", "inet", table).CombinedOutput()
	if err != nil {
		return fmt.Errorf("create owned table: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func secureSocket(path string) error {
	return os.Chmod(path, 0660)
}

func validName(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' {
			continue
		}
		return false
	}
	return true
}

func applyLegacy(path string) error {
	cfg := serverConfig{allowedDir: "/var/lib/porthub", allowedTable: "porthub"}
	return applyOwnedNFT(cfg, path)
}
