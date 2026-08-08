package main

import (
	"context"
	"net"
	"strings"
	"time"
)

// VerifyDNSRecord resolves the record's FQDN and reports whether it already
// points at the target value. When the
// domain already resolves to the target IP, an update can be skipped.
func verifyDNSRecord(record ddnsRecordItem, value string) (bool, error) {
	resolver := &net.Resolver{PreferGo: true}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	lookupType := "ip4"
	if record.RecordType == "AAAA" {
		lookupType = "ip6"
	}
	addrs, err := resolver.LookupIP(ctx, lookupType, record.FQDN)
	if err != nil {
		// NXDOMAIN / no records means the record does not exist yet.
		if isDNSNotFound(err) {
			return false, nil
		}
		return false, err
	}
	for _, addr := range addrs {
		if addr.String() == value {
			return true, nil
		}
	}
	return false, nil
}

func isDNSNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "no answer") ||
		strings.Contains(msg, "nxdomain") ||
		strings.Contains(msg, "server misbehaving")
}
