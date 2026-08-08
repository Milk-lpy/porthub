package snapshots

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

var acmeTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{10,256}$`)

type ACMEChallenge struct {
	Domain           string `json:"domain"`
	Token            string `json:"token"`
	KeyAuthorization string `json:"key_authorization"`
}

type ACMEChallengeSet struct {
	Version   int64           `json:"version"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Nonce     string          `json:"nonce"`
	Entries   []ACMEChallenge `json:"entries"`
	SHA256    string          `json:"sha256"`
	Signature string          `json:"signature"`
}

func SignACMEChallengeSet(set ACMEChallengeSet, privateKey ed25519.PrivateKey) (ACMEChallengeSet, error) {
	if set.Version < 1 {
		set.Version = time.Now().UnixNano()
	}
	set.CreatedAt = time.Now().UTC()
	if set.ExpiresAt.IsZero() {
		set.ExpiresAt = set.CreatedAt.Add(20 * time.Minute)
	}
	if err := validateACMEChallengeSet(set); err != nil {
		return set, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return set, err
	}
	set.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	canonical, _ := canonicalACMEChallengeSet(set)
	digest := sha256.Sum256(canonical)
	set.SHA256 = hex.EncodeToString(digest[:])
	set.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, digest[:]))
	return set, nil
}

func VerifyACMEChallengeSet(set ACMEChallengeSet, publicKey ed25519.PublicKey, now time.Time, nonceSeen func(string) bool) error {
	if err := validateACMEChallengeSet(set); err != nil {
		return err
	}
	if set.Nonce == "" {
		return errors.New("ACME challenge replay rejected")
	}
	if set.CreatedAt.After(now.Add(time.Minute)) || set.CreatedAt.Before(now.Add(-5*time.Minute)) || !set.ExpiresAt.After(now) {
		return errors.New("ACME challenge timestamp rejected")
	}
	canonical, _ := canonicalACMEChallengeSet(set)
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != set.SHA256 {
		return errors.New("ACME challenge hash mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(set.Signature)
	if err != nil || !ed25519.Verify(publicKey, digest[:], signature) {
		return errors.New("ACME challenge signature invalid")
	}
	// Record/check nonce only after the signature is verified, so invalid
	// payloads cannot burn a legitimate nonce.
	if nonceSeen(set.Nonce) {
		return errors.New("ACME challenge replay rejected")
	}
	return nil
}

func validateACMEChallengeSet(set ACMEChallengeSet) error {
	if set.Version < 1 || set.ExpiresAt.Sub(set.CreatedAt) > 30*time.Minute || len(set.Entries) > 20 {
		return errors.New("invalid ACME challenge set")
	}
	seen := map[string]bool{}
	for _, entry := range set.Entries {
		domain := strings.ToLower(strings.TrimSuffix(entry.Domain, "."))
		if domain == "" || strings.ContainsAny(domain, " /:@") || !acmeTokenPattern.MatchString(entry.Token) || len(entry.KeyAuthorization) < len(entry.Token)+10 || len(entry.KeyAuthorization) > 512 {
			return errors.New("invalid ACME challenge entry")
		}
		key := domain + "/" + entry.Token
		if seen[key] {
			return errors.New("duplicate ACME challenge entry")
		}
		seen[key] = true
	}
	return nil
}

func canonicalACMEChallengeSet(set ACMEChallengeSet) ([]byte, error) {
	set.SHA256, set.Signature = "", ""
	return json.Marshal(set)
}
