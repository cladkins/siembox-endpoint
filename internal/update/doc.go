// Package update implements the agent's self-update.
//
// The SIEMBox server only names a target version (models.AgentUpdateRequest).
// The agent downloads the release itself from the hardcoded GitHub repository
// over HTTPS using the system CA store, verifies the asset against the
// release's SHA256SUMS, and then runs the native installer matching how the
// agent was installed (deb, rpm, pkg, msi) or swaps its own binary (archive
// installs). The installer is launched detached from the agent's service
// because it restarts that service.
//
// This is self-maintenance of the agent, not a response action on the host.
package update
