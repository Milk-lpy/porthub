package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"porthub/internal/snapshots"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

var (
	acmeDirectoryURL = acme.LetsEncryptURL
	acmeAccountEmail string
	acmeIssueMu      sync.Mutex
	newACMEClient    = func(key crypto.Signer, directoryURL string) acmeClient {
		return &acme.Client{Key: key, DirectoryURL: directoryURL, UserAgent: "PortHub/0.4"}
	}
	pushACMEChallenges  = deployACMEChallenges
	publicACMEPreflight = verifyPublicACMEChallenges
)

type acmeClient interface {
	Register(context.Context, *acme.Account, func(string) bool) (*acme.Account, error)
	AuthorizeOrder(context.Context, []acme.AuthzID, ...acme.OrderOption) (*acme.Order, error)
	GetAuthorization(context.Context, string) (*acme.Authorization, error)
	HTTP01ChallengeResponse(string) (string, error)
	DNS01ChallengeRecord(string) (string, error)
	Accept(context.Context, *acme.Challenge) (*acme.Challenge, error)
	WaitAuthorization(context.Context, string) (*acme.Authorization, error)
	CreateOrderCert(context.Context, string, []byte, bool) ([][]byte, string, error)
}

type acmeIssueRequest struct {
	CertificateID int    `json:"certificate_id"`
	AcceptTOS     bool   `json:"accept_tos"`
	Deploy        bool   `json:"deploy"`
	Email         string `json:"email"`
}

type acmeRuntimeConfig struct {
	Email        string `json:"email"`
	DirectoryURL string `json:"directory_url"`
	Ready        bool   `json:"ready"`
}

type acmeIssueResult struct {
	OK            bool      `json:"ok"`
	CertificateID int       `json:"certificate_id"`
	Domains       []string  `json:"domains"`
	ExpiresAt     time.Time `json:"expires_at"`
	Deployed      bool      `json:"deployed"`
	Issuer        string    `json:"issuer"`
}

type acmeOrderSession struct {
	Context        context.Context
	Cancel         context.CancelFunc
	Client         acmeClient
	Order          *acme.Order
	CertificateKey *ecdsa.PrivateKey
	KeyPEM         []byte
}

func certificateACMEIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request acmeIssueRequest
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request) != nil || request.CertificateID < 1 || !request.AcceptTOS {
		http.Error(w, "certificate_id and ACME terms confirmation are required", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(request.Email) != "" {
		if err := saveACMEEmail(request.Email); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	cert, err := loadCertificate(request.CertificateID)
	if err != nil {
		http.Error(w, "certificate metadata not found", http.StatusNotFound)
		return
	}
	result, err := issueACMECertificate(cert, request.AcceptTOS, request.Deploy)
	if err != nil {
		setCertificateIssueFailure(cert.ID, err)
		audit(actor(r), "certificate_acme_failed", strconv.Itoa(cert.ID))
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	audit(actor(r), "certificate_acme_issued", strconv.Itoa(cert.ID))
	writeJSON(w, result)
}

func issueACMECertificate(cert certificateItem, acceptTOS, deploy bool) (acmeIssueResult, error) {
	switch cert.Mode {
	case "acme_http_01":
		return issueACMEHTTP01(cert, acceptTOS, deploy)
	case "acme_dns_01":
		return issueACMEDNS01(cert, acceptTOS, deploy)
	default:
		return acmeIssueResult{}, errors.New("enabled ACME certificate required")
	}
}

func certificateACMEStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, loadACMERuntimeConfig())
}

func issueACMEHTTP01(cert certificateItem, acceptTOS, deploy bool) (acmeIssueResult, error) {
	acmeIssueMu.Lock()
	defer acmeIssueMu.Unlock()
	if !cert.Enabled || cert.Mode != "acme_http_01" {
		return acmeIssueResult{}, errors.New("enabled ACME HTTP-01 certificate required")
	}
	for _, domain := range cert.Domains {
		if strings.HasPrefix(domain, "*.") {
			return acmeIssueResult{}, errors.New("wildcard certificate requires DNS-01")
		}
	}
	session, err := startACMEOrder(cert, acceptTOS)
	if err != nil {
		return acmeIssueResult{}, err
	}
	defer session.Cancel()
	type pendingAuthorization struct {
		URL       string
		Challenge *acme.Challenge
	}
	pending := []pendingAuthorization{}
	entries := []snapshots.ACMEChallenge{}
	for _, authorizationURL := range session.Order.AuthzURLs {
		authorization, err := session.Client.GetAuthorization(session.Context, authorizationURL)
		if err != nil {
			return acmeIssueResult{}, err
		}
		if authorization.Status == acme.StatusValid {
			continue
		}
		challenge := findHTTP01Challenge(authorization.Challenges)
		if challenge == nil {
			return acmeIssueResult{}, errors.New("ACME server did not offer HTTP-01")
		}
		keyAuthorization, err := session.Client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return acmeIssueResult{}, err
		}
		entries = append(entries, snapshots.ACMEChallenge{Domain: authorization.Identifier.Value, Token: challenge.Token, KeyAuthorization: keyAuthorization})
		pending = append(pending, pendingAuthorization{URL: authorizationURL, Challenge: challenge})
	}
	if len(entries) > 0 {
		if err := pushACMEChallenges(entries); err != nil {
			return acmeIssueResult{}, err
		}
		defer pushACMEChallenges(nil)
		if err := publicACMEPreflight(session.Context, entries); err != nil {
			return acmeIssueResult{}, err
		}
		for _, authorization := range pending {
			if _, err := session.Client.Accept(session.Context, authorization.Challenge); err != nil {
				return acmeIssueResult{}, err
			}
			if _, err := session.Client.WaitAuthorization(session.Context, authorization.URL); err != nil {
				return acmeIssueResult{}, err
			}
		}
	}
	return finalizeACMEOrder(session, cert, deploy)
}

func startACMEOrder(cert certificateItem, acceptTOS bool) (*acmeOrderSession, error) {
	if !acceptTOS {
		return nil, errors.New("ACME terms must be accepted")
	}
	config := loadACMERuntimeConfig()
	if !config.Ready {
		return nil, errors.New("ACME account email is not configured")
	}
	if !cert.Enabled {
		return nil, errors.New("enabled ACME certificate required")
	}
	if err := validateCertificateItem(cert); err != nil {
		return nil, err
	}
	keyPath := cert.KeyRef
	if keyPath == "" {
		keyPath = filepath.Join(dataDir, "certs", safeCertFileName(cert)+".key")
	}
	certificateKey, keyPEM, err := loadOrCreateECDSAKey(keyPath)
	if err != nil {
		return nil, err
	}
	accountKey, _, err := loadOrCreateECDSAKey(filepath.Join(dataDir, "acme", "account.key"))
	if err != nil {
		return nil, err
	}
	client := newACMEClient(accountKey, config.DirectoryURL)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	if _, err := client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + config.Email}}, func(string) bool { return acceptTOS }); err != nil && !isACMEAccountExists(err) {
		cancel()
		return nil, fmt.Errorf("ACME account registration failed: %w", err)
	}
	identifiers := make([]acme.AuthzID, 0, len(cert.Domains))
	for _, domain := range cert.Domains {
		identifiers = append(identifiers, acme.AuthzID{Type: "dns", Value: domain})
	}
	order, err := client.AuthorizeOrder(ctx, identifiers)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("ACME order failed: %w", err)
	}
	return &acmeOrderSession{Context: ctx, Cancel: cancel, Client: client, Order: order, CertificateKey: certificateKey, KeyPEM: keyPEM}, nil
}

func loadACMERuntimeConfig() acmeRuntimeConfig {
	config := acmeRuntimeConfig{Email: strings.TrimSpace(acmeAccountEmail), DirectoryURL: strings.TrimSpace(acmeDirectoryURL)}
	var storedEmail string
	if db.QueryRow("select email from acme_config where id=1").Scan(&storedEmail) == nil && strings.TrimSpace(storedEmail) != "" {
		config.Email = strings.TrimSpace(storedEmail)
	}
	config.Ready = validACMEEmail(config.Email) == nil && strings.HasPrefix(config.DirectoryURL, "https://")
	return config
}

func saveACMEEmail(value string) error {
	value = strings.TrimSpace(value)
	if err := validACMEEmail(value); err != nil {
		return err
	}
	_, err := db.Exec(`insert into acme_config(id,email,updated_at) values(1,?,?)
		on conflict(id) do update set email=excluded.email,updated_at=excluded.updated_at`, value, time.Now().UTC().Format(time.RFC3339))
	return err
}

func validACMEEmail(value string) error {
	if len(value) < 3 || len(value) > 254 {
		return errors.New("valid ACME contact email required")
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || !strings.Contains(value, "@") {
		return errors.New("valid ACME contact email required")
	}
	return nil
}

func deployACMEChallenges(entries []snapshots.ACMEChallenge) error {
	set, err := snapshots.SignACMEChallengeSet(snapshots.ACMEChallengeSet{Entries: entries}, priv)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(set)
	client, err := edgeHTTPClient()
	if err != nil {
		return err
	}
	request, _ := http.NewRequest(http.MethodPost, edgeURL+"/api/acme/challenges/apply", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode >= 300 {
		return errors.New(strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func verifyPublicACMEChallenges(ctx context.Context, entries []snapshots.ACMEChallenge) error {
	client := &http.Client{Timeout: 12 * time.Second}
	for _, entry := range entries {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+entry.Domain+"/.well-known/acme-challenge/"+entry.Token, nil)
		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf("public HTTP-01 preflight failed for %s: %w", entry.Domain, err)
		}
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		response.Body.Close()
		if response.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != entry.KeyAuthorization {
			return fmt.Errorf("public HTTP-01 path for %s does not reach PortHub Edge", entry.Domain)
		}
	}
	return nil
}

func loadOrCreateECDSAKey(path string) (*ecdsa.PrivateKey, []byte, error) {
	if err := validateUnderDataDir(path); err != nil {
		return nil, nil, err
	}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := writeCertificateKey(path); err != nil {
			return nil, nil, err
		}
		body, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, nil, errors.New("invalid ECDSA private key PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil || key.Curve != elliptic.P256() {
		return nil, nil, errors.New("ACME key must be ECDSA P-256")
	}
	return key, body, nil
}

func findHTTP01Challenge(challenges []*acme.Challenge) *acme.Challenge {
	for _, challenge := range challenges {
		if challenge.Type == "http-01" {
			return challenge
		}
	}
	return nil
}

func isACMEAccountExists(err error) bool {
	var acmeError *acme.Error
	return errors.As(err, &acmeError) && acmeError.StatusCode == http.StatusConflict
}

func setCertificateIssueFailure(id int, issueError error) {
	message := issueError.Error()
	if len(message) > 500 {
		message = message[:500]
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var currentStatus string
	_ = db.QueryRow("select status from certificates where id=?", id).Scan(&currentStatus)
	eventStatus, title := "failed", "ACME 证书申请失败"
	if currentStatus == "issued" {
		eventStatus = "deploy_failed"
		title = "ACME 证书已签发但部署失败"
	} else {
		_, _ = db.Exec("update certificates set status='failed',updated_at=? where id=?", now, id)
	}
	_, _ = db.Exec("insert into acme_orders(certificate_id,ts,status,directory_url,error) values(?,?,?,?,?)", id, now, eventStatus, acmeDirectoryURL, message)
	setControlAlert("certificate-acme:"+strconv.Itoa(id), "warning", title, message, true)
}

func acmeRenewalScheduler(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		rows, err := db.Query("select id from certificates where enabled=1 and mode in ('acme_http_01','acme_dns_01') and status='issued' and expires_at<>''")
		if err != nil {
			continue
		}
		ids := []int{}
		for rows.Next() {
			var id int
			if rows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
		for _, id := range ids {
			cert, err := loadCertificate(id)
			expires, _ := time.Parse(time.RFC3339, cert.ExpiresAt)
			if err == nil && time.Until(expires) <= 30*24*time.Hour {
				if _, err := issueACMECertificate(cert, true, true); err != nil {
					setCertificateIssueFailure(id, err)
				} else {
					setControlAlert("certificate-acme:"+strconv.Itoa(id), "warning", "ACME 证书申请失败", "", false)
				}
			}
		}
	}
}
