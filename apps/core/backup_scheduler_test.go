package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNextBackupDelay(t *testing.T) {
	now := time.Date(2026, 7, 31, 2, 30, 0, 0, time.UTC)
	if got := nextBackupDelay(now, 3); got != 30*time.Minute {
		t.Fatalf("delay = %s", got)
	}
	now = time.Date(2026, 7, 31, 3, 0, 0, 0, time.UTC)
	if got := nextBackupDelay(now, 3); got != 24*time.Hour {
		t.Fatalf("next-day delay = %s", got)
	}
}

func TestPruneCoreBackups(t *testing.T) {
	old := backupDir
	backupDir = t.TempDir()
	defer func() { backupDir = old }()

	for i := 0; i < 3; i++ {
		path := filepath.Join(backupDir, "core-20260731-00000"+string(rune('0'+i))+".tar.gz")
		if err := os.WriteFile(path, []byte("backup"), 0600); err != nil {
			t.Fatal(err)
		}
		stamp := time.Now().Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneCoreBackups(5); err != nil {
		t.Fatal(err)
	}
	if err := pruneCoreBackups(2); err != nil {
		t.Fatal(err)
	}
	items, err := listBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("backups = %d, want 2", len(items))
	}
}
