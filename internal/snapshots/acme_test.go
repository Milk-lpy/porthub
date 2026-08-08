package snapshots

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestSignedACMEChallengeSet(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	set, err := SignACMEChallengeSet(ACMEChallengeSet{Entries: []ACMEChallenge{{Domain: "nas.example.com", Token: "1234567890_token", KeyAuthorization: "1234567890_token.account-thumbprint"}}}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	check := func(value string) bool { old := seen[value]; seen[value] = true; return old }
	if err := VerifyACMEChallengeSet(set, publicKey, time.Now(), check); err != nil {
		t.Fatal(err)
	}
	if VerifyACMEChallengeSet(set, publicKey, time.Now(), check) == nil {
		t.Fatal("replayed challenge accepted")
	}
}
