package updater

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type InstallOptions struct {
	Root      string
	Version   string
	Component string
	Execute   bool
	Restart   func(string) error
	Healthy   func(string) error
	Now       func() time.Time
}

type InstallResult struct {
	OK         bool   `json:"ok"`
	DryRun     bool   `json:"dry_run"`
	Version    string `json:"version"`
	Component  string `json:"component"`
	Target     string `json:"target"`
	BackupDir  string `json:"backup_dir,omitempty"`
	RolledBack bool   `json:"rolled_back"`
}

func Install(options InstallOptions) (InstallResult, error) {
	if options.Component != "core" && options.Component != "agent" {
		return InstallResult{}, errors.New("component must be core or agent")
	}
	if options.Version == "" || filepath.Base(options.Version) != options.Version || strings.ContainsAny(options.Version, `/\\`) {
		return InstallResult{}, errors.New("valid version required")
	}
	root, err := cleanInstallRoot(options.Root)
	if err != nil {
		return InstallResult{}, err
	}
	stageDir := rooted(root, filepath.Join("/var/lib/porthub/updates", options.Version, options.Component))
	manifestBody, err := readBoundedFile(filepath.Join(stageDir, "manifest.json"), 1<<20)
	if err != nil {
		return InstallResult{}, errors.New("staged manifest unavailable")
	}
	var manifest Manifest
	if json.Unmarshal(manifestBody, &manifest) != nil || manifest.Version != options.Version {
		return InstallResult{}, errors.New("staged manifest/version mismatch")
	}
	publicKeyBody, err := readBoundedFile(rooted(root, "/etc/porthub/update-signing.pub"), 4096)
	if err != nil {
		return InstallResult{}, errors.New("update signing public key unavailable")
	}
	publicKey, err := ParsePublicKey(string(publicKeyBody))
	if err != nil || Verify(manifest, publicKey) != nil {
		return InstallResult{}, errors.New("staged manifest signature verification failed")
	}
	artifact, ok := manifest.Find(options.Component, runtime.GOOS, runtime.GOARCH)
	if !ok {
		return InstallResult{}, errors.New("manifest has no artifact for this host")
	}
	binaryName := "porthub-" + options.Component
	stagedBinary, err := readBoundedFile(filepath.Join(stageDir, binaryName), MaxArtifactBytes)
	if err != nil || VerifyArtifact(artifact, stagedBinary) != nil {
		return InstallResult{}, errors.New("staged artifact verification failed")
	}
	target := rooted(root, filepath.Join("/opt/porthub/bin", binaryName))
	result := InstallResult{OK: true, DryRun: !options.Execute, Version: options.Version, Component: options.Component, Target: target}
	if !options.Execute {
		return result, nil
	}
	if root == "" && os.Geteuid() != 0 {
		return InstallResult{}, errors.New("update installation requires root")
	}
	current, err := os.ReadFile(target)
	if err != nil {
		return InstallResult{}, errors.New("installed component unavailable")
	}
	mode := os.FileMode(0755)
	if info, statErr := os.Stat(target); statErr == nil {
		mode = info.Mode().Perm()
	}
	now := time.Now
	if options.Now != nil {
		now = options.Now
	}
	backupDir := rooted(root, filepath.Join("/var/backups/porthub", "update-"+now().UTC().Format("20060102-150405")+"-"+options.Component))
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return InstallResult{}, err
	}
	backupBinary := filepath.Join(backupDir, binaryName)
	if err := atomicInstallWrite(backupBinary, current, mode); err != nil {
		return InstallResult{}, err
	}
	if err := atomicInstallWrite(filepath.Join(backupDir, "manifest.json"), manifestBody, 0600); err != nil {
		return InstallResult{}, err
	}
	digest := sha256.Sum256(current)
	checksum := hex.EncodeToString(digest[:]) + "  " + binaryName + "\n"
	if err := atomicInstallWrite(filepath.Join(backupDir, "SHA256SUMS"), []byte(checksum), 0600); err != nil {
		return InstallResult{}, err
	}
	result.BackupDir = backupDir
	if err := atomicInstallWrite(target, stagedBinary, mode); err != nil {
		return InstallResult{}, err
	}
	restart := options.Restart
	healthy := options.Healthy
	if restart == nil {
		restart = restartComponent
	}
	if healthy == nil {
		healthy = waitComponentHealthy
	}
	if root != "" {
		if options.Restart == nil {
			restart = func(string) error { return nil }
		}
		if options.Healthy == nil {
			healthy = func(string) error { return nil }
		}
	}
	if err := restart(options.Component); err == nil {
		err = healthy(options.Component)
		if err == nil {
			return result, nil
		}
		return rollbackInstall(result, backupBinary, target, mode, restart, err)
	} else {
		return rollbackInstall(result, backupBinary, target, mode, restart, err)
	}
}

func rollbackInstall(result InstallResult, backupBinary, target string, mode os.FileMode, restart func(string) error, cause error) (InstallResult, error) {
	oldBinary, readErr := os.ReadFile(backupBinary)
	if readErr != nil {
		return result, fmt.Errorf("update failed and backup could not be read: %w", cause)
	}
	if err := atomicInstallWrite(target, oldBinary, mode); err != nil {
		return result, fmt.Errorf("update failed and rollback write failed: %v: %w", err, cause)
	}
	result.RolledBack = true
	_ = restart(result.Component)
	return result, fmt.Errorf("update health check failed; previous binary restored: %w", cause)
}

func cleanInstallRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", nil
	}
	clean, err := filepath.Abs(root)
	if err != nil || clean == "/" {
		return "", errors.New("test root must be an absolute non-root directory")
	}
	return clean, nil
}

func rooted(root, path string) string {
	if root == "" {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(path, "/"))
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	return body, nil
}

func atomicInstallWrite(path string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".porthub-install-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if temporary.Chmod(mode) != nil {
		temporary.Close()
		return errors.New("failed to set staged mode")
	}
	if _, err := temporary.Write(body); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		temporary.Close()
		return errors.New("failed to write staged file")
	}
	return os.Rename(temporaryPath, path)
}

func restartComponent(component string) error {
	return exec.Command("systemctl", "restart", "porthub-"+component+".service").Run()
}

func waitComponentHealthy(component string) error {
	endpoint := "https://127.0.0.1:9443/api/ready"
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if component == "agent" {
		endpoint = "http://127.0.0.1:9731/api/agent/status"
		client = &http.Client{Timeout: 2 * time.Second}
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if exec.Command("systemctl", "is-active", "--quiet", "porthub-"+component+".service").Run() == nil {
			response, err := client.Get(endpoint)
			if err == nil {
				response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
		time.Sleep(time.Second)
	}
	return errors.New("component did not become healthy within 30 seconds")
}
