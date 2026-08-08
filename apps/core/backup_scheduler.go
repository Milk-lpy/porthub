package main

import (
	"log"
	"os"
	"sort"
	"time"
)

var backupRetention int
var backupHourUTC int

func backupScheduler() {
	for {
		delay := nextBackupDelay(time.Now().UTC(), backupHourUTC)
		timer := time.NewTimer(delay)
		<-timer.C
		info, err := createCoreBackup()
		if err != nil {
			log.Printf("scheduled backup failed: %v", err)
			audit("system", "backup_scheduled_failed", err.Error())
			continue
		}
		if err := pruneCoreBackups(backupRetention); err != nil {
			log.Printf("backup retention failed: %v", err)
		}
		audit("system", "backup_scheduled", info.Name)
	}
}

func nextBackupDelay(now time.Time, hourUTC int) time.Duration {
	if hourUTC < 0 || hourUTC > 23 {
		hourUTC = 3
	}
	next := time.Date(now.Year(), now.Month(), now.Day(), hourUTC, 0, 0, 0, time.UTC)
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next.Sub(now)
}

func pruneCoreBackups(retain int) error {
	if retain < 1 {
		return nil
	}
	items, err := listBackups()
	if err != nil {
		return err
	}
	if len(items) <= retain {
		return nil
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt > items[j].CreatedAt })
	for _, item := range items[retain:] {
		if err := os.Remove(item.Path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
