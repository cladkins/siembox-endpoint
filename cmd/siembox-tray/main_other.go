//go:build !darwin

// Command siembox-tray is the SIEMBox Endpoint macOS menu bar app. It is only built
// for macOS; on other platforms it is a stub so the module still builds.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "siembox-tray is only supported on macOS")
	os.Exit(1)
}
