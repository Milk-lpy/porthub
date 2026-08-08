package main

import "testing"

func TestParseProcNetLine(t *testing.T) {
	line := "  0: 00000000:24D7 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1"
	port, state, ok := parseProcNetLine(line)
	if !ok || port != 9431 || state != "0A" {
		t.Fatalf("unexpected parse: port=%d state=%s ok=%v", port, state, ok)
	}
	if _, _, ok := parseProcNetLine("sl local_address rem_address st"); ok {
		t.Fatal("header should not parse")
	}
}
