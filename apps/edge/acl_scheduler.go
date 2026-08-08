package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"porthub/internal/nftables"
	"time"
)

func scheduledACLRefresh() {
	for range time.NewTicker(30 * time.Second).C {
		mu.Lock()
		if !snapshotHasScheduledACL() {
			mu.Unlock()
			continue
		}
		rules, err := nftables.CompileAt(current, "wg-porthub", time.Now().UTC())
		if err != nil {
			mu.Unlock()
			log.Printf("scheduled ACL compile failed: %v", err)
			continue
		}
		currentPath := filepath.Join(data, "current.nft")
		existing, _ := os.ReadFile(currentPath)
		if bytes.Equal(existing, []byte(rules)) {
			mu.Unlock()
			continue
		}
		temporary, writeErr := writeNFTCandidate("scheduled-acl.nft", []byte(rules))
		if writeErr != nil {
			err = writeErr
		} else if err = edgeNetdApplyNFT(temporary); err != nil {
			log.Printf("scheduled ACL apply failed: %v", err)
		} else {
			err = os.WriteFile(currentPath, []byte(rules), 0600)
		}
		mu.Unlock()
		if err == nil {
			log.Println("scheduled ACL state applied")
		}
	}
}

func snapshotHasScheduledACL() bool {
	for _, rule := range current.ACLRules {
		if rule.Enabled && rule.StartTime != "" {
			return true
		}
	}
	return false
}
