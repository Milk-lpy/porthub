package auth

import (
	"testing"
	"time"
)

func TestPasswordHashAndStrength(t *testing.T) {
	if ValidatePassword("short") == nil {
		t.Fatal("expected weak password rejection")
	}
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword("correct horse battery", hash) || CheckPassword("wrong horse battery", hash) {
		t.Fatal("password hash check failed")
	}
}

func TestTOTP(t *testing.T) {
	secret := NewTOTPSecret()
	code, err := TOTP(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := VerifyTOTP(secret, code); !ok {
		t.Fatal("totp verification failed")
	}
}
