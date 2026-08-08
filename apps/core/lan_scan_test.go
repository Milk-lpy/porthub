package main

import (
	"net"
	"testing"
)

func TestPrepareLanScanUsesManagedNetwork(t *testing.T) {
	old := coreForwardConfig
	_, network, _ := net.ParseCIDR("192.168.50.0/30")
	coreForwardConfig.LANCIDRs = []*net.IPNet{network}
	defer func() { coreForwardConfig = old }()

	mode, hosts, ports, err := prepareLanScan(lanScanRequest{Mode: "common"})
	if err != nil || mode != "common" || len(hosts) != 2 || len(ports) != len(commonScanPorts) {
		t.Fatalf("unexpected common scan: mode=%s hosts=%v ports=%d err=%v", mode, hosts, len(ports), err)
	}
	mode, hosts, ports, err = prepareLanScan(lanScanRequest{Mode: "deep"})
	if err != nil || mode != "deep" || len(hosts) != 2 || len(ports) != 65535 {
		t.Fatalf("unexpected global deep scan: mode=%s hosts=%v ports=%d err=%v", mode, hosts, len(ports), err)
	}
	if _, _, _, err := prepareLanScan(lanScanRequest{Mode: "common", Host: "192.168.51.2"}); err == nil {
		t.Fatal("host outside managed LAN must be rejected")
	}
}

func TestPrepareDeepScanCoversGlobalNetwork(t *testing.T) {
	old := coreForwardConfig
	_, network, _ := net.ParseCIDR("192.168.50.0/24")
	coreForwardConfig.LANCIDRs = []*net.IPNet{network}
	defer func() { coreForwardConfig = old }()

	mode, hosts, ports, err := prepareLanScan(lanScanRequest{Mode: "deep"})
	if err != nil || mode != "deep" || len(hosts) != 254 || len(ports) != 65535 {
		t.Fatalf("unexpected deep scan: mode=%s hosts=%v ports=%d err=%v", mode, hosts, len(ports), err)
	}
}

func TestClassifyHostPrefersSpecificInfrastructure(t *testing.T) {
	ports := []lanScanPort{{Port: 8006, Category: "虚拟化"}, {Port: 22, Category: "远程管理"}}
	if got := classifyHost(ports); got != "虚拟化" {
		t.Fatalf("classification=%q", got)
	}
	unknown := []lanScanPort{{Port: 4242, Category: "未分类"}}
	if got := classifyHost(unknown); got != "Linux / 未分类" {
		t.Fatalf("unknown classification=%q", got)
	}
}
