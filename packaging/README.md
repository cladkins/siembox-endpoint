# Packaging

Build artifacts and OS install integration for the SIEMBox Endpoint agent.

## Layout
- `agent.json.template` — default config shipped to `/etc/siembox-agent/agent.json.template`.
- `linux/postinstall.sh`, `linux/preremove.sh` — `.deb`/`.rpm` lifecycle hooks (nfpm). The post-install hook fetches osquery + grype and registers the service.
- `darwin/install.sh` — macOS (launchd) installer. **Reviewed, not yet validated on a Mac.**
- `windows/install.ps1` — Windows service installer. **Reviewed, not yet validated on Windows.**

The standalone Linux installer for non-package installs is `../scripts/install.sh`.

## Building artifacts

Uses [goreleaser](https://goreleaser.com) (config: `../.goreleaser.yaml`).

```sh
make snapshot     # build binaries + .deb/.rpm + archives locally (no publish)
goreleaser check  # validate the config
goreleaser release --clean   # tagged release (CI / maintainers)
```

Outputs land in `dist/`: per-OS/arch archives (`tar.gz`, `zip` for Windows),
`.deb`/`.rpm` Linux packages, and `checksums.txt`.

## Dependency model

osquery and grype are **fetched at install time** (kept out of the agent
package to stay lean). The agent runs without them — it just logs that the
corresponding module is disabled — so a failed dependency fetch never blocks
installation.

## Service

Service registration uses [`kardianos/service`](https://github.com/kardianos/service),
which targets the host's init system automatically: **systemd** or **SysV** on
Linux, **launchd** on macOS, and the **Service Control Manager** on Windows. The
agent subcommands `install`/`uninstall`/`start`/`stop`/`status` wrap it.
