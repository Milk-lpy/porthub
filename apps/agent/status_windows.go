//go:build windows

package main

import (
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func loadAvg() []float64 { return nil }

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func memInfo() map[string]uint64 {
	mod := windows.NewLazySystemDLL("kernel32.dll")
	proc := mod.NewProc("GlobalMemoryStatusEx")
	status := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&status)))
	if ret == 0 {
		return nil
	}
	return map[string]uint64{
		"MemTotal":     status.TotalPhys / 1024,
		"MemAvailable": status.AvailPhys / 1024,
		"SwapTotal":    status.TotalPageFile / 1024,
		"SwapFree":     status.AvailPageFile / 1024,
	}
}

func diskRoot() map[string]uint64 {
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	path, err := windows.UTF16PtrFromString(drive + `\`)
	if err != nil {
		return nil
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(path, &free, &total, &totalFree); err != nil {
		return nil
	}
	return map[string]uint64{"total": total, "free": free}
}

func netDev() []netCounter {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]netCounter, 0, len(ifaces))
	for _, iface := range ifaces {
		row := windows.MibIfRow{Index: uint32(iface.Index)}
		if err := windows.GetIfEntry(&row); err != nil {
			continue
		}
		out = append(out, netCounter{Name: iface.Name, RXBytes: uint64(row.InOctets), TXBytes: uint64(row.OutOctets)})
	}
	return out
}
