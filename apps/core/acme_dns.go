package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

type acmeDNSCleanup func() error

var (
	publishACMEDNSTXT = publishACMEDNSChallenge
	waitACMEDNSTXT    = waitForACMEDNSTXT
)

func issueACMEDNS01(cert certificateItem, acceptTOS, deploy bool) (acmeIssueResult, error) {
	acmeIssueMu.Lock()
	defer acmeIssueMu.Unlock()
	if !cert.Enabled || cert.Mode != "acme_dns_01" || cert.DNSProviderID < 1 {
		return acmeIssueResult{}, errors.New("enabled ACME DNS-01 certificate with provider required")
	}
	provider, err := loadDDNSProvider(cert.DNSProviderID)
	if err != nil || !provider.Enabled {
		return acmeIssueResult{}, errors.New("enabled DNS provider not found")
	}
	if provider.Type != "cloudflare" && provider.Type != "webhook" {
		return acmeIssueResult{}, errors.New("DNS-01 currently supports Cloudflare or webhook providers")
	}
	session, err := startACMEOrder(cert, acceptTOS)
	if err != nil {
		return acmeIssueResult{}, err
	}
	defer session.Cancel()
	type pendingAuthorization struct {
		URL       string
		Challenge *acme.Challenge
		FQDN      string
		Value     string
	}
	pending := []pendingAuthorization{}
	cleanups := []acmeDNSCleanup{}
	defer func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			if err := cleanups[i](); err != nil {
				log.Printf("ACME DNS-01 cleanup failed: %v", err)
			}
		}
	}()
	for _, authorizationURL := range session.Order.AuthzURLs {
		authorization, err := session.Client.GetAuthorization(session.Context, authorizationURL)
		if err != nil {
			return acmeIssueResult{}, err
		}
		if authorization.Status == acme.StatusValid {
			continue
		}
		challenge := findChallenge(authorization.Challenges, "dns-01")
		if challenge == nil {
			return acmeIssueResult{}, errors.New("ACME server did not offer DNS-01")
		}
		value, err := session.Client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			return acmeIssueResult{}, err
		}
		fqdn := "_acme-challenge." + strings.TrimPrefix(normalizeDNSName(authorization.Identifier.Value), "*.")
		cleanup, err := publishACMEDNSTXT(provider, fqdn, value)
		if err != nil {
			return acmeIssueResult{}, err
		}
		cleanups = append(cleanups, cleanup)
		pending = append(pending, pendingAuthorization{URL: authorizationURL, Challenge: challenge, FQDN: fqdn, Value: value})
	}
	for _, authorization := range pending {
		if err := waitACMEDNSTXT(session.Context, authorization.FQDN, authorization.Value); err != nil {
			return acmeIssueResult{}, err
		}
		if _, err := session.Client.Accept(session.Context, authorization.Challenge); err != nil {
			return acmeIssueResult{}, err
		}
		if _, err := session.Client.WaitAuthorization(session.Context, authorization.URL); err != nil {
			return acmeIssueResult{}, err
		}
	}
	return finalizeACMEOrder(session, cert, deploy)
}

func findChallenge(challenges []*acme.Challenge, kind string) *acme.Challenge {
	for _, challenge := range challenges {
		if challenge.Type == kind {
			return challenge
		}
	}
	return nil
}

func publishACMEDNSChallenge(provider ddnsProviderItem, fqdn, value string) (acmeDNSCleanup, error) {
	switch provider.Type {
	case "cloudflare":
		return publishCloudflareACME(provider, fqdn, value)
	case "webhook":
		return publishWebhookACME(provider, fqdn, value)
	default:
		return nil, errors.New("unsupported DNS-01 provider")
	}
}

func publishCloudflareACME(provider ddnsProviderItem, fqdn, value string) (acmeDNSCleanup, error) {
	cfg, err := cloudflareConfig(provider.Config)
	if err != nil {
		return nil, err
	}
	token, err := readProviderSecret(provider.SecretRef)
	if err != nil || token == "" {
		return nil, errors.New("Cloudflare token secret_ref required")
	}
	endpoint := cfg.EndpointBase + "/zones/" + url.PathEscape(cfg.ZoneID) + "/dns_records"
	body, _ := json.Marshal(map[string]any{"type": "TXT", "name": fqdn, "content": value, "ttl": 120})
	var response struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := cloudflareRequest(http.MethodPost, endpoint, token, body, &response); err != nil {
		return nil, err
	}
	if !response.Success || response.Result.ID == "" {
		return nil, errors.New("Cloudflare did not return the created DNS record id")
	}
	deleteURL := endpoint + "/" + url.PathEscape(response.Result.ID)
	return func() error { return cloudflareRequest(http.MethodDelete, deleteURL, token, nil, nil) }, nil
}

func publishWebhookACME(provider ddnsProviderItem, fqdn, value string) (acmeDNSCleanup, error) {
	endpoint, err := webhookEndpoint(provider.Config)
	if err != nil {
		return nil, err
	}
	secret, err := readProviderSecret(provider.SecretRef)
	if err != nil {
		return nil, err
	}
	request := func(action string) error {
		body, _ := json.Marshal(map[string]any{"action": action, "fqdn": fqdn, "record_type": "TXT", "value": value, "ttl": 120})
		req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		req.Header.Set("content-type", "application/json")
		if secret != "" {
			req.Header.Set("authorization", "Bearer "+secret)
		}
		client, err := acmeWebhookClient(endpoint)
		if err != nil {
			return err
		}
		response, err := client.Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		if response.StatusCode >= 300 {
			return fmt.Errorf("DNS webhook %s failed: HTTP %d %s", action, response.StatusCode, strings.TrimSpace(string(responseBody)))
		}
		return nil
	}
	if err := request("present"); err != nil {
		return nil, err
	}
	return func() error { return request("cleanup") }, nil
}

func acmeWebhookClient(endpoint string) (*http.Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if localHTTP(u) {
		return &http.Client{Timeout: 10 * time.Second}, nil
	}
	if u.Scheme != "https" {
		return nil, errors.New("DNS webhook must use public HTTPS or localhost HTTP")
	}
	return newSafeIPFeedClient(endpoint)
}

func waitForACMEDNSTXT(ctx context.Context, fqdn, expected string) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		values, err := net.DefaultResolver.LookupTXT(ctx, fqdn)
		if err == nil {
			for _, value := range values {
				if value == expected {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("DNS-01 TXT record for %s did not propagate: %w", fqdn, ctx.Err())
		case <-ticker.C:
		}
	}
}
