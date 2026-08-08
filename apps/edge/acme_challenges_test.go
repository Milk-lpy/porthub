package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"porthub/internal/snapshots"
	"testing"
	"time"
)

func TestSignedACMEChallengeApplyAndServe(t *testing.T) {
	oldData, oldPub, oldNonces := data, pub, nonces
	data = t.TempDir()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	pub, nonces = publicKey, map[string]time.Time{}
	acmeChallenges.Lock()
	acmeChallenges.set = snapshots.ACMEChallengeSet{}
	acmeChallenges.Unlock()
	defer func() { data, pub, nonces = oldData, oldPub, oldNonces }()

	set, err := snapshots.SignACMEChallengeSet(snapshots.ACMEChallengeSet{Entries: []snapshots.ACMEChallenge{{Domain: "nas.example.com", Token: "1234567890_token", KeyAuthorization: "1234567890_token.account-thumbprint"}}}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(set)
	recorder := httptest.NewRecorder()
	applyACMEChallenges(recorder, httptest.NewRequest(http.MethodPost, "/api/acme/challenges/apply", bytes.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("apply failed: %d %s", recorder.Code, recorder.Body.String())
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://nas.example.com/.well-known/acme-challenge/1234567890_token", nil)
	request.Host = "nas.example.com"
	if !serveACMEChallenge(response, request) || response.Body.String() != "1234567890_token.account-thumbprint" {
		t.Fatalf("challenge not served: %d %q", response.Code, response.Body.String())
	}
}
