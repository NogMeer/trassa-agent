# trassa-agent

[Русский](README.md) · **English**

The agent for servers managed with **Trassa**. Trassa installs this program on your VPS. It connects the server to the panel: it sends metrics and logs, and runs the operations you approve in the panel.

The source is open so that anyone can verify what runs on their server.

> [!IMPORTANT]
> **Status: in development.** The agent and helper code is here, but there are no signed releases yet, so the agent cannot be installed. The rest of this README describes the design; these are commitments the implementation is built against.

---

## What is Trassa

Trassa is a panel for your own network of servers at any hosting provider. All your VPSs are visible in one place: what runs on them, how loaded they are, when they need paying for. Routine tasks need no command line: updates, firewall, backups, service restarts, app releases.

Trassa is not a hosting provider and not a VPN. Your servers stay yours, at your provider. Trassa manages them.

## Why an agent and not SSH

The panel could manage servers over SSH. But then it would need permanent root access to all your servers, and any vulnerability in the panel would become a vulnerability in your infrastructure. The agent works differently:

| | SSH from the panel | trassa-agent |
|---|---|---|
| Who initiates the connection | The panel logs into the server | The server connects to the panel itself |
| Inbound ports | SSH must be open | None, works behind NAT |
| What the panel can run | Any command as root | Only operations from a fixed catalog |
| If the channel or gateway is compromised | Full access to the server | Nothing runs without the panel's signature |
| A mistake in network or SSH rules | Easy to lose the server | The agent reverts to the previous state on its own |

Manual work is still possible. For that, Trassa will offer a web terminal using short-lived SSH certificates, with session recording.

## How it works

### Two processes

| Process | User | What it does |
|---|---|---|
| `trassa-agent` | `trassa`, unprivileged | Holds the connection to the panel, collects metrics and logs, verifies operation signatures |
| `trassa-helper` | `root` | Listens only on a local Unix socket and runs operations from a list compiled into the binary |

The networked process has no root rights. The root process does not touch the network.

### Connection

- The agent opens an outbound WSS connection on port 443. It opens no inbound ports.
- Messages are protobuf; the schema lives in [`proto/`](proto/).
- A heartbeat is sent every 20 seconds. After a disconnect the agent reconnects with an increasing delay, capped at 60 seconds.

### Signed operations

Every action on a server is an operation of a specific type, such as `firewall.apply`, `service.restart` or `packages.upgrade`. The panel signs it with an Ed25519 key kept separately from the connection gateway. The agent runs an operation only if all of these hold:

- the signature is valid;
- the operation is addressed to this exact server;
- it has not expired (usually 5 minutes);
- its nonce has not been seen before;
- its type is in the catalog and its parameters pass schema validation.

### Risk, approval and rollback

| Class | Examples | Approval in the panel | Rollback |
|---|---|---|---|
| `READ` | System info, ports, logs | Not needed | — |
| `CHANGE` | Service restart, security updates, backup | A click | Config copy or previous release |
| `DESTRUCTIVE` | Firewall, SSH and users, restore from backup, reboot | Second factor | Required |

Before a change, the agent saves the affected files. If the panel does not confirm connectivity after a network or SSH change, the agent reverts to the previous state on its own, even with no connection to the panel. After each operation the agent checks the result: the service is running, the port answers, SSH login works.

### Arbitrary commands

Running arbitrary commands (`exec.run`) is **off by default**. It can only be enabled in `/etc/trassa/agent.toml` on the server itself (`allow_exec = true`); the panel cannot change that file. Even when enabled, commands go through hard blocks:

- `curl | sh` and the like;
- writing to `authorized_keys`;
- disabling the firewall or logging.

Every run also needs approval, and the signed operation must carry a hoster snapshot. The file must be owned by root and not writable by group or others, otherwise commands stay off. Turning it off takes effect at once; after turning it on, restart `trassa-helper` and `trassa-agent` so the panel sees the capability. There is no shell: the command arrives as a list of words (`argv`) and is executed directly, with no pipelines, substitutions or globs; shells, interpreters and programs that run other commands (`sudo`, `env`, `xargs`, `find -exec`…) are blocked. The program is looked up in a fixed `PATH`, run by its full path after symlinks, and only if it is an unmodified distribution package file (checked against dpkg md5sums) in `/usr/bin`, `/usr/sbin`, `/bin` or `/sbin`, owned by root together with its directories. System secret files (`/etc/shadow`, SSH host keys, `/etc/ssl/private`, `/root/.ssh` and others) are inaccessible in the service. It runs in a transient systemd service as the chosen user: Trassa directories are inaccessible there, on timeout (up to 300 seconds) all of its processes are stopped, and output (up to 256 KiB) goes to the operation log with secrets removed.

## What the agent cannot do by design

- Accept inbound connections.
- Run anything without a valid panel signature.
- See your hosting provider tokens: they exist only in the panel.
- Send the contents of your files, except in operations that exist for that purpose: reading logs on request and backups.

## Supported systems

First wave: Ubuntu 22.04, 24.04 and 26.04, Debian 12 and 13, on amd64 and arm64. Installing Docker for apps (E17) on Ubuntu 26.04 is not supported yet. On other systems the installer stops with a clear message.

## Installation and removal

The agent is installed with a single command that the Trassa panel gives you:

1. The installer downloads the binary and verifies its [minisign](https://jedisct1.github.io/minisign/) signature and checksum.
2. The agent generates an Ed25519 key on the server itself.
3. The agent registers with a one-time token that is valid for 15 minutes.

For providers without cloud-init, the panel can install the agent once over SSH, using a key you added yourself.

To remove the agent, use the panel or run `trassa-agent uninstall` on the server. The agent stops its services and removes its files and user; the server keeps running without Trassa.

Updates are signed and rolled out in waves. If a new version fails to start, the agent goes back to the previous one. You can pin a version.

## Signing in from your computer: `trassa`

`trassa` runs on your computer (macOS, Linux, Windows), not on the server.

```
trassa login --url https://app.example.com   # approve the code in the panel; the token goes to the system keyring
trassa servers                               # your servers and logins
trassa ssh web-1                             # terminal through Trassa: no open SSH port needed
trassa ssh --direct web-1                    # a 10-minute certificate and the system ssh straight to the server (macOS, Linux)
trassa logout                                # revoke the sign-in and remove the token
```

The sign-in token is kept in the Keychain (macOS), Secret Service (Linux) or Credential Manager (Windows). Without a keyring, for example on a server with no D-Bus session, the token is stored in `credentials.json` with mode 0600 next to the settings. In `--direct` mode a fresh Ed25519 key is created for each sign-in and lives only in memory. ssh gets it through a read-only agent run by `trassa`, the host key comes from the panel, and ssh configuration files are not read (`-F none`).

## Repository layout

| Path | Contents |
|---|---|
| [`proto/trassa/agent/v1/`](proto/trassa/agent/v1/) | The agent–panel channel contract (protobuf) |
| `cmd/trassa-agent`, `cmd/trassa-helper` | The two processes: unprivileged network process and root helper |
| `cmd/trassa`, `internal/cli` | The `trassa` program for your own computer: device-code sign-in (RFC 8628), token in the system keyring, server list, sign-in through Trassa (terminal WebSocket) and `--direct` (in-memory key, 10-minute certificate, system ssh) |
| `internal/channel`, `internal/identity`, `internal/enroll` | WSS channel, agent key, enrollment. Moving to another panel (`agent.rebind`, E24): the helper rewrites the enrollment with a rollback point and auto-return, signature checks switch to the new panel's keys at once; the agent re-reads the enrollment before every connection, connects to the new address with normal TLS verification against system roots and waits for a `SignedConfirm` of this operation signed by a new panel key. An untrusted certificate, a rejected handshake or three failed connections in a row return at once, otherwise at the deadline (60–600 s), with result `REBIND_ROLLED_BACK` and the reason |
| `internal/helper`, `internal/helperrpc`, `internal/ops`, `internal/nonce` | Helper: socket with caller uid check, built-in operation list, signature, expiry and nonce checks |
| `internal/rollback`, `internal/autorollback` | Rollback points and timer-based auto-rollback via systemd |
| `internal/metrics` | Server metrics from `/proc` and `statfs` without root: a batch every 15 s, kept for up to 10 minutes while offline |
| `internal/security` (detector) | Watching in the helper: new keys, jobs, units, SUID files, users, processes from /tmp, preloaded libraries, outbound to suspicious ports, sustained CPU — at most one event per hour; “I did this” is `security.baseline.accept` |
| `internal/wireguard` | Private network (WireGuard): the helper creates the key and never exports it, the interface is set up via netlink and wgctrl from a desired-state file, forwarding only on the network interface, a block in `/etc/hosts`, one `DOCKER-USER` rule on a hub with Docker, auto-rollback |
| `internal/opcheck`, `internal/netcheck` | Signed-operation checks shared by the helper and the agent; `net.check` — a single TCP connect check run by the unprivileged agent |
| `internal/security` | Security center: `security.scan` runs read-only checks from a built-in list (SSH, users, permissions, ports, firewall, updates, disks, certificates, kernel, Docker); `packages.list_updates` reads updates from the apt cache without network access |
| `internal/fsinspect` | Reads for the AI operator (E20): `disk.usage` — disk usage like `du -x` from `/` or a root from a built-in list, depth up to 3, up to 20 entries, symlinks not followed; `config.read` — one file up to 64 KiB from `/etc/nginx/**`, `/etc/systemd/system/*.service`, `/etc/docker/daemon.json` and Trassa app compose files, never keys, `.env`, `.htpasswd` or Trassa units; the path after symlinks is checked on the open descriptor and the content goes through the secret filter |
| `internal/helper/execpolicy`, `internal/helper/execrun` | `exec.run` (E20): the `allow_exec` flag from `/etc/trassa/agent.toml` is checked first, `argv` without a shell, R28 blocks use the same rules as the panel (shared set `proto/testdata/exec-policy.json`) plus paths after symlinks; the run is `systemd-run` with the program's full path, user, working directory, timeout and output limit |
| `internal/vpnprobe` | VPN pack probe point (E25): `vpn.probe.ensure` installs Xray-core from a built-in table (the agent downloads, the helper checks sha256), `vpn.probe.run` measures a chain with a test access: the helper decrypts the access and builds the engine config itself from a vless/trojan/ss link (one outbound to the pinned IP from `allowed_endpoints`, socks inbound on 127.0.0.1 only); the engine runs as a separate `trassa-vpnprobe` user in a transient systemd service with no capabilities, an IP filter, Trassa directories hidden and memory and time limits |
| `internal/logsrc`, `internal/logs` | Logs via a signed `logs.subscribe`: the helper reads them (journald without a shell, files only inside `/var/log/` without symlinks, containers via the Docker API, a Trassa app (`APP`) — all its containers by the `trassa.app_id` label, previous releases included) and redacts secrets before they leave root; the agent spools up to 50 MB and sends until acknowledged. `logs.read` returns the latest lines on request. App memory and CPU (`app_mem_used_bytes`, `app_cpu_usage_percent` labelled `app_id`) are computed by the helper from Docker stats and handed to the agent via `app.stats` |
| `internal/events`, `internal/queue` | Local thresholds (failed service, disk at 90%, memory at 95% for over a minute) and delivery of frames acknowledged by the gateway |
| `internal/update`, `internal/uninstall`, `internal/redact`, `internal/sysinfo` | minisign-verified updates, uninstall, secret redaction in output, system facts |
| [`scripts/install.sh`](scripts/install.sh), [`packaging/systemd/`](packaging/systemd/) | Installer and service units |
| `test/stubpanel`, `scripts/ci-matrix.sh`, `tools/release-sign`, `scripts/release-gate.sh` | CI OS matrix against a stub panel, release signing and the pre-publish check |

Updates are downloaded by the network process; the helper never goes online, it only verifies the signature and checksums of what was downloaded and installs the binaries.

Build and checks: Go 1.26, `make tools`, then `make check` (protobuf codegen, `go vet`, staticcheck, tests in the regular build and with the internal `testops` tag, release binary check, building `trassa` for macOS, Linux and Windows). The test operation `test.config_write` exists only in builds with the `testops` tag; `make release-check` verifies the release binary does not contain it. CI on every commit: the OS matrix (Ubuntu 22.04, 24.04 and 26.04, Debian 12 and 13 on amd64 and arm64 in containers with systemd: install with the panel command, refusal on a tampered signature, coming online, `system.info`, reinstall, removal; the report is the `matrix-report-*` artifact) and a release build on two runners with a `sha256` comparison.

## Verifying a release

Releases are reproducible: anyone building the same tag gets the same bytes.

```sh
git clone https://github.com/NogMeer/trassa-agent && cd trassa-agent
git checkout v1.2.3
make release VERSION=1.2.3    # needs Go 1.26+; it downloads the exact compiler from go.mod (GOTOOLCHAIN=auto)
diff dist/SHA256SUMS <(curl -fsSL https://github.com/NogMeer/trassa-agent/releases/download/v1.2.3/SHA256SUMS)
```

`SHA256SUMS` is signed with [minisign](https://jedisct1.github.io/minisign/); the keys are in `TRASSA_RELEASE_KEYS` in [`scripts/install.sh`](scripts/install.sh):

```sh
minisign -V -P <key> -m SHA256SUMS    # trusted comment: trassa-agent 1.2.3
sha256sum -c SHA256SUMS
```

Release key `trassa-release-1` (key id `9889674CCEE25046`):

```
RWRGUOLOTGeJmFfIFOk0UF9AXhgfoh1qZK2h8eRTZNCa23uNDmvfNCSp
```

An unsigned release is never published: `scripts/release-gate.sh` checks the signature with the same code and keys as `install.sh`.

`install.sh` of release 0.1.0: sha256 `11cf7e1b3742290d4df63916de21adc16560ed79e97b095fed80d4dc05ee14e4`. Check it before running:

```sh
curl -fsSL --proto '=https' -o install.sh https://agents.trassa.one/install.sh
shasum -a 256 install.sh
```

## Security

Found a vulnerability? Please do not open a public issue. Report it through a [private GitHub report](https://github.com/NogMeer/trassa-agent/security/advisories/new). See [SECURITY.md](SECURITY.md) for details.

## License

- The agent code is licensed under [GNU AGPL-3.0](LICENSE). You are free to use, study and modify it. If you distribute a modified version or make it available over a network, you must release its source under the same terms.
- The protocol schema in [`proto/`](proto/) is licensed under [Apache-2.0](proto/LICENSE), so protocol clients can be generated without restrictions.

**Trademark.** The licenses grant rights to the code, not to the name. "Trassa" and the Trassa logo may not be used for forks or third-party services in a way that makes them look like Trassa or endorsed by us. A fork must use a different name.

## Contributing

Until the agent is released we are not accepting code changes. Questions and design suggestions are welcome in issues.
