// Package version exposes the agent build version. The value is overridden at
// build time via -ldflags "-X .../internal/version.Version=v1.2.3".
package version

// Version is the agent's semantic version. "dev" in unstamped builds.
var Version = "dev"
