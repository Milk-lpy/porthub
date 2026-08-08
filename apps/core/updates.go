package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"porthub/internal/updater"
	"runtime"
	"strings"
	"time"
)

var (
	buildVersion            = "0.4.0"
	updateManifestURL       string
	updatePublicKeyPath     string
	updateStageDir          string
	updateHTTPClientFactory = newSafeIPFeedClient
)

type updateActionRequest struct {
	Component string `json:"component"`
}

type updateStatus struct {
	Enabled         bool   `json:"enabled"`
	CurrentVersion  string `json:"current_version"`
	ManifestURL     string `json:"manifest_url,omitempty"`
	LatestVersion   string `json:"latest_version,omitempty"`
	LastCheckedAt   string `json:"last_checked_at,omitempty"`
	LastStatus      string `json:"last_status,omitempty"`
	LastError       string `json:"last_error,omitempty"`
	StagedVersion   string `json:"staged_version,omitempty"`
	StagedComponent string `json:"staged_component,omitempty"`
	StagedPath      string `json:"staged_path,omitempty"`
}

func updatesStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, loadUpdateStatus())
}

func updatesCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	manifest, _, err := fetchUpdateManifest()
	if err != nil {
		recordUpdateEvent("check_failed", "", "", err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	recordUpdateEvent("checked", manifest.Version, "", "")
	audit(actor(r), "update_check", manifest.Version)
	writeJSON(w, map[string]any{
		"ok": true, "current_version": buildVersion, "latest_version": manifest.Version,
		"published_at": manifest.PublishedAt, "notes": manifest.Notes,
		"available": manifest.Version != buildVersion,
	})
}

func updatesStage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request updateActionRequest
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request) != nil {
		http.Error(w, "invalid update request", http.StatusBadRequest)
		return
	}
	request.Component = strings.ToLower(strings.TrimSpace(request.Component))
	if request.Component != "core" && request.Component != "agent" {
		http.Error(w, "only core and agent can be staged on this node", http.StatusBadRequest)
		return
	}
	manifest, publicKey, err := fetchUpdateManifest()
	if err != nil {
		recordUpdateEvent("stage_failed", "", request.Component, err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	artifact, ok := manifest.Find(request.Component, runtime.GOOS, runtime.GOARCH)
	if !ok {
		http.Error(w, "manifest has no artifact for this component and platform", http.StatusNotFound)
		return
	}
	body, err := fetchUpdateArtifact(artifact)
	if err != nil {
		recordUpdateEvent("stage_failed", manifest.Version, request.Component, err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	stagePath, err := writeUpdateStage(manifest, publicKey, artifact, body)
	if err != nil {
		recordUpdateEvent("stage_failed", manifest.Version, request.Component, err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	recordUpdateEvent("staged", manifest.Version, request.Component, "")
	audit(actor(r), "update_stage", request.Component+" "+manifest.Version)
	writeJSON(w, map[string]any{"ok": true, "version": manifest.Version, "component": request.Component, "stage_path": stagePath, "requires_install_confirmation": true})
}

func fetchUpdateManifest() (updater.Manifest, ed25519.PublicKey, error) {
	if updateManifestURL == "" || updatePublicKeyPath == "" {
		return updater.Manifest{}, nil, errors.New("update source is not configured")
	}
	publicKeyBody, err := os.ReadFile(updatePublicKeyPath)
	if err != nil {
		return updater.Manifest{}, nil, errors.New("update signing public key is unavailable")
	}
	publicKey, err := updater.ParsePublicKey(string(publicKeyBody))
	if err != nil {
		return updater.Manifest{}, nil, err
	}
	body, err := fetchUpdateURL(updateManifestURL, 1<<20)
	if err != nil {
		return updater.Manifest{}, nil, err
	}
	var manifest updater.Manifest
	if json.Unmarshal(body, &manifest) != nil {
		return updater.Manifest{}, nil, errors.New("invalid update manifest JSON")
	}
	if err := updater.Verify(manifest, publicKey); err != nil {
		return updater.Manifest{}, nil, err
	}
	return manifest, publicKey, nil
}

func fetchUpdateArtifact(artifact updater.Artifact) ([]byte, error) {
	body, err := fetchUpdateURL(artifact.URL, updater.MaxArtifactBytes)
	if err != nil {
		return nil, err
	}
	if err := updater.VerifyArtifact(artifact, body); err != nil {
		return nil, err
	}
	return body, nil
}

func fetchUpdateURL(rawURL string, limit int64) ([]byte, error) {
	client, err := updateHTTPClientFactory(rawURL)
	if err != nil {
		return nil, err
	}
	request, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	request.Header.Set("User-Agent", "PortHub-Updater/1.0")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update server returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("update response exceeds size limit")
	}
	return body, nil
}

func writeUpdateStage(manifest updater.Manifest, publicKey ed25519.PublicKey, artifact updater.Artifact, body []byte) (string, error) {
	if err := updater.Verify(manifest, publicKey); err != nil {
		return "", err
	}
	if err := updater.VerifyArtifact(artifact, body); err != nil {
		return "", err
	}
	dir := filepath.Join(updateStageDir, manifest.Version, artifact.Component)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", err
	}
	binaryPath := filepath.Join(dir, "porthub-"+artifact.Component)
	if err := atomicUpdateWrite(binaryPath, body, 0750); err != nil {
		return "", err
	}
	manifestBody, _ := json.MarshalIndent(manifest, "", "  ")
	if err := atomicUpdateWrite(filepath.Join(dir, "manifest.json"), manifestBody, 0640); err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	metadata := []byte("component=" + artifact.Component + "\nversion=" + manifest.Version + "\nsha256=" + hex.EncodeToString(digest[:]) + "\n")
	if err := atomicUpdateWrite(filepath.Join(dir, "stage.meta"), metadata, 0640); err != nil {
		return "", err
	}
	return dir, nil
}

func atomicUpdateWrite(path string, body []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".porthub-update-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if temporary.Chmod(mode) != nil || writeAllSync(temporary, body) != nil || temporary.Close() != nil {
		temporary.Close()
		return errors.New("failed to write staged update")
	}
	return os.Rename(temporaryPath, path)
}

func writeAllSync(file *os.File, body []byte) error {
	if _, err := file.Write(body); err != nil {
		return err
	}
	return file.Sync()
}

func recordUpdateEvent(status, version, component, message string) {
	if len(message) > 500 {
		message = message[:500]
	}
	_, _ = db.Exec("insert into update_events(ts,status,version,component,message) values(?,?,?,?,?)", time.Now().UTC().Format(time.RFC3339), status, version, component, message)
}

func loadUpdateStatus() updateStatus {
	status := updateStatus{Enabled: updateManifestURL != "" && updatePublicKeyPath != "", CurrentVersion: buildVersion, ManifestURL: updateManifestURL}
	var component string
	_ = db.QueryRow("select ts,status,version,component,message from update_events order by id desc limit 1").Scan(&status.LastCheckedAt, &status.LastStatus, &status.LatestVersion, &component, &status.LastError)
	if status.LastStatus == "staged" {
		status.StagedVersion = status.LatestVersion
		status.StagedComponent = component
		status.StagedPath = filepath.Join(updateStageDir, status.StagedVersion, component)
	}
	return status
}
