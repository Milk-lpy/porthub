//go:build windows

package main

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	afInet               = 2
	afInet6              = 23
	tcpTableOwnerPIDAll  = 5
	udpTableOwnerPID     = 1
	mibTCPStateListen    = 2
	errorInsufficientBuf = 122
)

var (
	iphlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCP = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDP = iphlpapi.NewProc("GetExtendedUdpTable")
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

type mibUDP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPID    uint32
}

func discoverListeners() []listener {
	var out []listener
	out = append(out, tcp4Listeners()...)
	out = append(out, tcp6Listeners()...)
	out = append(out, udp4Listeners()...)
	out = append(out, udp6Listeners()...)
	return out
}

func discoverPlatform() string { return "windows" }

func discoverContainers() []discoveredContainer { return []discoveredContainer{} }

func tcp4Listeners() []listener {
	buf, ok := extendedTCPTable(afInet)
	if !ok || len(buf) < 4 {
		return nil
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	base := uintptr(unsafe.Pointer(&buf[4]))
	step := unsafe.Sizeof(mibTCPRowOwnerPID{})
	out := make([]listener, 0, count)
	for i := uint32(0); i < count; i++ {
		row := (*mibTCPRowOwnerPID)(unsafe.Pointer(base + uintptr(i)*step))
		if row.State != mibTCPStateListen {
			continue
		}
		out = append(out, listener{Protocol: "tcp", Address: ipv4(row.LocalAddr), Port: networkPort(row.LocalPort)})
	}
	return out
}

func tcp6Listeners() []listener {
	buf, ok := extendedTCPTable(afInet6)
	if !ok || len(buf) < 4 {
		return nil
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	base := uintptr(unsafe.Pointer(&buf[4]))
	step := unsafe.Sizeof(mibTCP6RowOwnerPID{})
	out := make([]listener, 0, count)
	for i := uint32(0); i < count; i++ {
		row := (*mibTCP6RowOwnerPID)(unsafe.Pointer(base + uintptr(i)*step))
		if row.State != mibTCPStateListen {
			continue
		}
		out = append(out, listener{Protocol: "tcp6", Address: net.IP(row.LocalAddr[:]).String(), Port: networkPort(row.LocalPort)})
	}
	return out
}

func udp4Listeners() []listener {
	buf, ok := extendedUDPTable(afInet)
	if !ok || len(buf) < 4 {
		return nil
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	base := uintptr(unsafe.Pointer(&buf[4]))
	step := unsafe.Sizeof(mibUDPRowOwnerPID{})
	out := make([]listener, 0, count)
	for i := uint32(0); i < count; i++ {
		row := (*mibUDPRowOwnerPID)(unsafe.Pointer(base + uintptr(i)*step))
		out = append(out, listener{Protocol: "udp", Address: ipv4(row.LocalAddr), Port: networkPort(row.LocalPort)})
	}
	return out
}

func udp6Listeners() []listener {
	buf, ok := extendedUDPTable(afInet6)
	if !ok || len(buf) < 4 {
		return nil
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	base := uintptr(unsafe.Pointer(&buf[4]))
	step := unsafe.Sizeof(mibUDP6RowOwnerPID{})
	out := make([]listener, 0, count)
	for i := uint32(0); i < count; i++ {
		row := (*mibUDP6RowOwnerPID)(unsafe.Pointer(base + uintptr(i)*step))
		out = append(out, listener{Protocol: "udp6", Address: net.IP(row.LocalAddr[:]).String(), Port: networkPort(row.LocalPort)})
	}
	return out
}

func extendedTCPTable(family uint32) ([]byte, bool) {
	var size uint32
	rc, _, _ := procGetExtendedTCP.Call(0, uintptr(unsafe.Pointer(&size)), 1, uintptr(family), uintptr(tcpTableOwnerPIDAll), 0)
	if rc != errorInsufficientBuf || size == 0 {
		return nil, false
	}
	buf := make([]byte, size)
	rc, _, _ = procGetExtendedTCP.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(family), uintptr(tcpTableOwnerPIDAll), 0)
	return buf, rc == 0
}

func extendedUDPTable(family uint32) ([]byte, bool) {
	var size uint32
	rc, _, _ := procGetExtendedUDP.Call(0, uintptr(unsafe.Pointer(&size)), 1, uintptr(family), uintptr(udpTableOwnerPID), 0)
	if rc != errorInsufficientBuf || size == 0 {
		return nil, false
	}
	buf := make([]byte, size)
	rc, _, _ = procGetExtendedUDP.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(family), uintptr(udpTableOwnerPID), 0)
	return buf, rc == 0
}

func networkPort(raw uint32) int {
	return int((raw>>8)&0xff | (raw&0xff)<<8)
}

func ipv4(raw uint32) string {
	return net.IPv4(byte(raw), byte(raw>>8), byte(raw>>16), byte(raw>>24)).String()
}
