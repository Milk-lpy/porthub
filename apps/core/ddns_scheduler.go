package main

import (
	"log"
	"time"
)

func ddnsScheduler(interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	for range time.NewTicker(interval).C {
		if err := runDueDDNSSyncs(time.Now().UTC()); err != nil {
			log.Printf("ddns scheduler failed: %v", err)
		}
	}
}

func runDueDDNSSyncs(now time.Time) error {
	rows, err := db.Query(`select id from ddns_records where enabled=1 order by id`)
	if err != nil {
		return err
	}
	var ids []int
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		record, err := loadDDNSRecord(id)
		if err != nil || !ddnsSyncDue(record, now) {
			continue
		}
		provider, err := loadDDNSProvider(record.ProviderID)
		if err != nil || !provider.Enabled {
			result := ddnsSyncResult{OK: false, RecordID: id, FQDN: record.FQDN, Action: "provider_unavailable", Message: "provider disabled or unavailable"}
			updateDDNSSyncState(record, "", result)
			notifyDDNSResult(record, result, "")
			continue
		}
		value, err := resolveDDNSValue(record, "", false)
		if err != nil {
			result := ddnsSyncResult{OK: false, RecordID: id, FQDN: record.FQDN, Action: "address_unavailable", Message: err.Error()}
			updateDDNSSyncState(record, "", result)
			notifyDDNSResult(record, result, "")
			continue
		}
		if value == record.LastValue && record.LastSyncAt != "" && !forceDDNSSync(record, now) {
			db.Exec("update ddns_records set last_sync_at=?,last_error='',failure_count=0 where id=?", now.Format(time.RFC3339), record.ID)
			continue
		}
		// If DNS already resolves to the target value, skip the API call.
		if record.VerifyDNS {
			if matches, verr := verifyDNSRecord(record, value); verr == nil && matches {
				result := ddnsSyncResult{OK: true, RecordID: id, FQDN: record.FQDN, RecordType: record.RecordType, TargetValue: value, Action: "dns_already_matches", Message: "域名解析已是目标 IP，跳过更新"}
				updateDDNSSyncState(record, value, result)
				continue
			}
		}
		result := executeDDNSSync(record, provider, value, false)
		updateDDNSSyncState(record, value, result)
		notifyDDNSResult(record, result, value)
		audit("system", "ddns_scheduled_sync", result.Action+" "+record.FQDN)
	}
	return nil
}

// forceDDNSSync reports whether the record's force interval has elapsed.
func forceDDNSSync(record ddnsRecordItem, now time.Time) bool {
	if record.ForceInterval < 60 {
		return false
	}
	last, err := time.Parse(time.RFC3339, record.LastSyncAt)
	if err != nil {
		return true
	}
	return now.Sub(last) >= time.Duration(record.ForceInterval)*time.Second
}

func ddnsSyncDue(record ddnsRecordItem, now time.Time) bool {
	interval := time.Duration(record.Interval) * time.Second
	if interval < time.Minute {
		interval = 5 * time.Minute
	}
	if record.FailureCount > 0 {
		shift := record.FailureCount - 1
		if shift > 5 {
			shift = 5
		}
		interval *= time.Duration(1 << shift)
		if interval > time.Hour {
			interval = time.Hour
		}
	}
	last, err := time.Parse(time.RFC3339, record.LastSyncAt)
	return err != nil || !now.Before(last.Add(interval))
}

func updateDDNSSyncState(record ddnsRecordItem, value string, result ddnsSyncResult) {
	now := time.Now().UTC().Format(time.RFC3339)
	if result.OK {
		db.Exec("update ddns_records set last_value=?,last_sync_at=?,last_error='',failure_count=0,updated_at=? where id=?", value, now, now, record.ID)
		return
	}
	failures := record.FailureCount + 1
	db.Exec("update ddns_records set last_sync_at=?,last_error=?,failure_count=?,updated_at=? where id=?", now, result.Message, failures, now, record.ID)
	log.Printf("ddns sync failed record=%d fqdn=%q failures=%d: %s", record.ID, record.FQDN, failures, result.Message)
	if failures == 1 || failures == 3 {
		audit("system", "ddns_sync_alert", record.FQDN+": "+result.Message)
	}
}
