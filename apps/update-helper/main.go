package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"porthub/internal/updater"
)

func main() {
	var options updater.InstallOptions
	flag.StringVar(&options.Version, "version", "", "staged version to install")
	flag.StringVar(&options.Component, "component", "", "core or agent")
	flag.BoolVar(&options.Execute, "execute", false, "install and restart; default is dry-run")
	flag.StringVar(&options.Root, "root", "", "test-only filesystem root; systemd actions are skipped")
	flag.Parse()
	result, err := updater.Install(options)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if result.Component != "" {
			_ = json.NewEncoder(os.Stderr).Encode(result)
		}
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
