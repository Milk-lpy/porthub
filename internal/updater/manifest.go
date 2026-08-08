package updater

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const MaxArtifactBytes int64 = 128 << 20

var (
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
	shaPattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Manifest struct {
	Version     string     `json:"version"`
	PublishedAt time.Time  `json:"published_at"`
	Notes       string     `json:"notes,omitempty"`
	Artifacts   []Artifact `json:"artifacts"`
	Signature   string     `json:"signature"`
}

type Artifact struct {
	Component string `json:"component"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
}

func (manifest Manifest) Validate() error {
	if !versionPattern.MatchString(manifest.Version) {
		return errors.New("invalid update version")
	}
	if manifest.PublishedAt.IsZero() || manifest.PublishedAt.After(time.Now().UTC().Add(10*time.Minute)) {
		return errors.New("invalid update publication time")
	}
	if len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > 20 {
		return errors.New("update manifest must contain 1-20 artifacts")
	}
	seen := map[string]bool{}
	for _, artifact := range manifest.Artifacts {
		if err := artifact.Validate(); err != nil {
			return err
		}
		key := artifact.Component + "/" + artifact.OS + "/" + artifact.Arch
		if seen[key] {
			return fmt.Errorf("duplicate update artifact %s", key)
		}
		seen[key] = true
	}
	return nil
}

func (artifact Artifact) Validate() error {
	components := map[string]bool{"core": true, "edge": true, "agent": true, "netd": true}
	oses := map[string]bool{"linux": true, "windows": true}
	arches := map[string]bool{"amd64": true, "arm64": true}
	if !components[artifact.Component] || !oses[artifact.OS] || !arches[artifact.Arch] {
		return errors.New("update artifact has unsupported component, OS or architecture")
	}
	parsed, err := url.Parse(artifact.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return errors.New("update artifact URL must be HTTPS without credentials")
	}
	if !shaPattern.MatchString(strings.ToLower(artifact.SHA256)) {
		return errors.New("update artifact has invalid SHA256")
	}
	if artifact.Size < 1 || artifact.Size > MaxArtifactBytes {
		return errors.New("update artifact size is outside the allowed range")
	}
	return nil
}

func (manifest Manifest) Find(component, osName, arch string) (Artifact, bool) {
	for _, artifact := range manifest.Artifacts {
		if artifact.Component == component && artifact.OS == osName && artifact.Arch == arch {
			return artifact, true
		}
	}
	return Artifact{}, false
}

func Sign(manifest Manifest, privateKey ed25519.PrivateKey) (Manifest, error) {
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	digest, err := manifestDigest(manifest)
	if err != nil {
		return Manifest{}, err
	}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, digest))
	return manifest, nil
}

func Verify(manifest Manifest, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid update signing public key")
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid update manifest signature encoding")
	}
	digest, err := manifestDigest(manifest)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, digest, signature) {
		return errors.New("update manifest signature verification failed")
	}
	return nil
}

func VerifyArtifact(artifact Artifact, body []byte) error {
	if int64(len(body)) != artifact.Size {
		return errors.New("update artifact size does not match manifest")
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != strings.ToLower(artifact.SHA256) {
		return errors.New("update artifact SHA256 does not match manifest")
	}
	return nil
}

func manifestDigest(manifest Manifest) ([]byte, error) {
	manifest.Signature = ""
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}

func ParsePublicKey(value string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("update public key must be base64 Ed25519")
	}
	return ed25519.PublicKey(decoded), nil
}
