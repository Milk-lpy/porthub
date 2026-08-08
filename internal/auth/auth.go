package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
	"time"
)

func RandomPassword() string {
	b := make([]byte, 18)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	sum := argon2.IDKey([]byte(pw), salt, 3, 64*1024, 2, 32)
	return fmt.Sprintf("argon2id$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum)), nil
}
func CheckPassword(pw, enc string) bool {
	parts := strings.Split(enc, "$")
	if len(parts) != 3 {
		return false
	}
	salt, _ := base64.RawStdEncoding.DecodeString(parts[1])
	want, _ := base64.RawStdEncoding.DecodeString(parts[2])
	got := argon2.IDKey([]byte(pw), salt, 3, 64*1024, 2, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
func NewTOTPSecret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
func TOTP(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix() / 30)
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)
	h := hmac.New(sha1.New, key)
	h.Write(msg)
	s := h.Sum(nil)
	o := s[len(s)-1] & 15
	code := (int(s[o]&0x7f) << 24) | (int(s[o+1]) << 16) | (int(s[o+2]) << 8) | int(s[o+3])
	return fmt.Sprintf("%06d", code%1000000), nil
}

// VerifyTOTP checks a 6-digit TOTP code against secret within ±1 step.
// Returns the accepted counter value (floor(unix/30)) and true on success,
// or 0 and false on failure. The caller must compare the returned counter
// against the stored lastCounter and only accept if counter > lastCounter.
func VerifyTOTP(secret, code string) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	now := time.Now()
	for i := int64(-1); i <= 1; i++ {
		t := now.Add(time.Duration(i) * 30 * time.Second)
		counter := t.Unix() / 30
		c, err := TOTP(secret, t)
		if err == nil && subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
			return counter, true
		}
	}
	return 0, false
}
func ValidatePassword(p string) error {
	if len(p) < 12 {
		return errors.New("password too short")
	}
	return nil
}
