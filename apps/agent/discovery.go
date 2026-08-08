package main

import (
	"net/http"
)

type listener struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
}

type discoveredContainer struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Image  string          `json:"image"`
	State  string          `json:"state"`
	Status string          `json:"status"`
	Ports  []containerPort `json:"ports"`
}

type containerPort struct {
	IP          string `json:"ip,omitempty"`
	PrivatePort int    `json:"private_port"`
	PublicPort  int    `json:"public_port,omitempty"`
	Protocol    string `json:"protocol"`
}

type discoveryResult struct {
	Platform   string                `json:"platform"`
	Listeners  []listener            `json:"listeners"`
	Containers []discoveredContainer `json:"containers"`
}

func collectDiscovery() discoveryResult {
	return discoveryResult{Platform: discoverPlatform(), Listeners: discoverListeners(), Containers: discoverContainers()}
}

func discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, collectDiscovery())
}
