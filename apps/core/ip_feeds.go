package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"porthub/internal/snapshots"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxIPFeedBytes = 5 << 20

type ipFeedItem struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	Action         string `json:"action"`
	URL            string `json:"url"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	RefreshHours   int    `json:"refresh_hours"`
	Enabled        bool   `json:"enabled"`
	IPSetID        int    `json:"ip_set_id"`
	LastFetchAt    string `json:"last_fetch_at,omitempty"`
	LastSHA256     string `json:"last_sha256,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	CreatedAt      string `json:"created_at,omitempty"`
	UpdatedAt      string `json:"updated_at,omitempty"`
}

type ipFeedSyncRequest struct {
	ID     int  `json:"id"`
	DryRun bool `json:"dry_run"`
}

type ipFeedSyncResult struct {
	OK      bool   `json:"ok"`
	DryRun  bool   `json:"dry_run"`
	FeedID  int    `json:"feed_id"`
	IPSetID int    `json:"ip_set_id"`
	Count   int    `json:"count"`
	SHA256  string `json:"sha256"`
}

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var ipFeedClientFactory = newSafeIPFeedClient

func ipFeeds(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, loadIPFeeds())
	case http.MethodPost:
		var item ipFeedItem
		if json.NewDecoder(r.Body).Decode(&item) != nil {
			http.Error(w, "invalid IP feed", http.StatusBadRequest)
			return
		}
		if err := normalizeIPFeed(&item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		result, err := db.Exec(`insert into ip_feeds(name,kind,action,url,expected_sha256,refresh_hours,enabled,ip_set_id,last_fetch_at,last_sha256,last_error,created_at,updated_at) values(?,?,?,?,?,?,?,0,'','','',?,?)`,
			item.Name, item.Kind, item.Action, item.URL, item.ExpectedSHA256, item.RefreshHours, boolInt(item.Enabled), now, now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		id, _ := result.LastInsertId()
		audit(actor(r), "ip_feed_create", strconv.FormatInt(id, 10))
		writeJSON(w, map[string]any{"ok": true, "id": id})
	case http.MethodPut:
		var item ipFeedItem
		if json.NewDecoder(r.Body).Decode(&item) != nil || item.ID < 1 {
			http.Error(w, "valid feed id required", http.StatusBadRequest)
			return
		}
		if err := normalizeIPFeed(&item); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, err := db.Exec(`update ip_feeds set name=?,kind=?,action=?,url=?,expected_sha256=?,refresh_hours=?,enabled=?,updated_at=? where id=?`,
			item.Name, item.Kind, item.Action, item.URL, item.ExpectedSHA256, item.RefreshHours, boolInt(item.Enabled), time.Now().UTC().Format(time.RFC3339), item.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit(actor(r), "ip_feed_update", strconv.Itoa(item.ID))
		writeJSON(w, map[string]any{"ok": true})
	case http.MethodDelete:
		deleteByID(w, r, "ip_feeds", "ip_feed_delete")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func ipFeedSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request ipFeedSyncRequest
	if json.NewDecoder(r.Body).Decode(&request) != nil || request.ID < 1 {
		http.Error(w, "feed id required", http.StatusBadRequest)
		return
	}
	result, err := syncIPFeed(request.ID, request.DryRun)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	audit(actor(r), "ip_feed_sync", strconv.Itoa(request.ID)+" "+strconv.Itoa(result.Count))
	writeJSON(w, result)
}

func normalizeIPFeed(item *ipFeedItem) error {
	item.Name, item.Kind, item.Action = strings.TrimSpace(item.Name), strings.ToLower(strings.TrimSpace(item.Kind)), strings.ToLower(strings.TrimSpace(item.Action))
	item.URL, item.ExpectedSHA256 = strings.TrimSpace(item.URL), strings.ToLower(strings.TrimSpace(item.ExpectedSHA256))
	if item.Name == "" || len(item.Name) > 128 || (item.Kind != "geoip" && item.Kind != "asn") {
		return errors.New("feed name and kind (geoip/asn) are required")
	}
	if item.Action != "allow" && item.Action != "deny" {
		return errors.New("feed action must be allow or deny")
	}
	if _, err := validatePublicHTTPSURL(item.URL); err != nil {
		return err
	}
	if item.ExpectedSHA256 != "" && !sha256Pattern.MatchString(item.ExpectedSHA256) {
		return errors.New("expected_sha256 must be a 64-character lowercase hash")
	}
	if item.RefreshHours == 0 {
		item.RefreshHours = 24
	}
	if item.RefreshHours < 1 || item.RefreshHours > 720 {
		return errors.New("refresh_hours must be 1-720")
	}
	return nil
}

func syncIPFeed(id int, dryRun bool) (ipFeedSyncResult, error) {
	item, err := loadIPFeed(id)
	if err != nil {
		return ipFeedSyncResult{}, err
	}
	if !item.Enabled && !dryRun {
		return ipFeedSyncResult{}, errors.New("IP feed is disabled")
	}
	body, digest, err := fetchIPFeed(item.URL)
	if err != nil {
		updateIPFeedError(id, err)
		return ipFeedSyncResult{}, err
	}
	if item.ExpectedSHA256 != "" && item.ExpectedSHA256 != digest {
		err = errors.New("IP feed SHA256 does not match the pinned value")
		updateIPFeedError(id, err)
		return ipFeedSyncResult{}, err
	}
	cidrs, err := parseCIDRImport(string(body))
	if err != nil || len(cidrs) > maxImportedCIDRs {
		if err == nil {
			err = errors.New("IP feed contains too many CIDRs")
		}
		updateIPFeedError(id, err)
		return ipFeedSyncResult{}, err
	}
	result := ipFeedSyncResult{OK: true, DryRun: dryRun, FeedID: id, IPSetID: item.IPSetID, Count: len(cidrs), SHA256: digest}
	if dryRun {
		return result, nil
	}
	set := snapshots.IPSet{ID: strconv.Itoa(item.IPSetID), Name: item.Name, Kind: item.Kind, Action: snapshots.ACLAction(item.Action), CIDRs: cidrs, Enabled: true}
	if err := snapshots.ValidateIPSets([]snapshots.IPSet{set}); err != nil {
		return result, err
	}
	cidrsJSON, _ := json.Marshal(cidrs)
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := db.Begin()
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if item.IPSetID > 0 {
		update, execErr := tx.Exec("update ip_sets set name=?,kind=?,action=?,cidrs=?,enabled=1,updated_at=? where id=?", item.Name, item.Kind, item.Action, string(cidrsJSON), now, item.IPSetID)
		if execErr != nil {
			return result, execErr
		}
		if affected, _ := update.RowsAffected(); affected == 0 {
			item.IPSetID = 0
		}
	}
	if item.IPSetID == 0 {
		insert, execErr := tx.Exec("insert into ip_sets(name,kind,action,cidrs,enabled,created_at,updated_at) values(?,?,?,?,1,?,?)", item.Name, item.Kind, item.Action, string(cidrsJSON), now, now)
		if execErr != nil {
			return result, execErr
		}
		newID, _ := insert.LastInsertId()
		item.IPSetID, result.IPSetID = int(newID), int(newID)
	}
	if _, err := tx.Exec("update ip_feeds set ip_set_id=?,last_fetch_at=?,last_sha256=?,last_error='',updated_at=? where id=?", item.IPSetID, now, digest, now, id); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

func fetchIPFeed(rawURL string) ([]byte, string, error) {
	client, err := ipFeedClientFactory(rawURL)
	if err != nil {
		return nil, "", err
	}
	request, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	request.Header.Set("User-Agent", "PortHub-IPFeed/1.0")
	response, err := client.Do(request)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("IP feed returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxIPFeedBytes+1))
	if err != nil || len(body) > maxIPFeedBytes {
		return nil, "", errors.New("IP feed exceeds 5 MiB")
	}
	digest := sha256.Sum256(body)
	return body, hex.EncodeToString(digest[:]), nil
}

func newSafeIPFeedClient(rawURL string) (*http.Client, error) {
	_, err := validatePublicHTTPSURL(rawURL)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			if publicFeedIP(address.IP) {
				return dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
			}
		}
		return nil, errors.New("IP feed host resolves only to private or reserved addresses")
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("too many IP feed redirects")
		}
		_, err := validatePublicHTTPSURL(request.URL.String())
		return err
	}
	return client, nil
}

func validatePublicHTTPSURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return nil, errors.New("IP feed URL must be public HTTPS without credentials")
	}
	if ip := net.ParseIP(parsed.Hostname()); ip != nil && !publicFeedIP(ip) {
		return nil, errors.New("IP feed URL may not target private or reserved addresses")
	}
	return parsed, nil
}

func publicFeedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	// RFC 6598 CGNAT (includes Alibaba Cloud metadata 100.100.100.200)
	if ip4 := ip.To4(); ip4 != nil && cgnat4.Contains(ip4) {
		return false
	}
	return true
}

func loadIPFeeds() []ipFeedItem {
	rows, err := db.Query(`select id,name,kind,action,url,coalesce(expected_sha256,''),coalesce(refresh_hours,24),enabled,coalesce(ip_set_id,0),coalesce(last_fetch_at,''),coalesce(last_sha256,''),coalesce(last_error,''),coalesce(created_at,''),coalesce(updated_at,'') from ip_feeds order by id`)
	if err != nil {
		return []ipFeedItem{}
	}
	defer rows.Close()
	items := []ipFeedItem{}
	for rows.Next() {
		var item ipFeedItem
		var enabled int
		if rows.Scan(&item.ID, &item.Name, &item.Kind, &item.Action, &item.URL, &item.ExpectedSHA256, &item.RefreshHours, &enabled, &item.IPSetID, &item.LastFetchAt, &item.LastSHA256, &item.LastError, &item.CreatedAt, &item.UpdatedAt) == nil {
			item.Enabled = enabled == 1
			items = append(items, item)
		}
	}
	return items
}

func loadIPFeed(id int) (ipFeedItem, error) {
	for _, item := range loadIPFeeds() {
		if item.ID == id {
			return item, nil
		}
	}
	return ipFeedItem{}, errors.New("IP feed not found")
}

func updateIPFeedError(id int, err error) {
	if err == nil {
		return
	}
	message := err.Error()
	if len(message) > 500 {
		message = message[:500]
	}
	db.Exec("update ip_feeds set last_fetch_at=?,last_error=?,updated_at=? where id=?", time.Now().UTC().Format(time.RFC3339), message, time.Now().UTC().Format(time.RFC3339), id)
}

func ipFeedScheduler(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		for _, item := range loadIPFeeds() {
			last, _ := time.Parse(time.RFC3339, item.LastFetchAt)
			if item.Enabled && (last.IsZero() || now.Sub(last) >= time.Duration(item.RefreshHours)*time.Hour) {
				if _, err := syncIPFeed(item.ID, false); err != nil {
					setControlAlert("ip-feed:"+strconv.Itoa(item.ID), "warning", "IP 数据源同步失败", item.Name+": "+err.Error(), true)
				} else {
					setControlAlert("ip-feed:"+strconv.Itoa(item.ID), "warning", "IP 数据源同步失败", "", false)
				}
			}
		}
	}
}
