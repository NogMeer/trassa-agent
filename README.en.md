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

Every run also needs approval.

## What the agent cannot do by design

- Accept inbound connections.
- Run anything without a valid panel signature.
- See your hosting provider tokens: they exist only in the panel.
- Send the contents of your files, except in operations that exist for that purpose: reading logs on request and backups.

## Supported systems

First wave: Ubuntu 22.04 and 24.04, Debian 12 and 13, on amd64 and arm64. On other systems the installer stops with a clear message.

## Installation and removal

The agent is installed with a single command that the Trassa panel gives you:

1. The installer downloads the binary and verifies its [minisign](https://jedisct1.github.io/minisign/) signature and checksum.
2. The agent generates an Ed25519 key on the server itself.
3. The agent registers with a one-time token that is valid for 15 minutes.

For providers without cloud-init, the panel can install the agent once over SSH, using a key you added yourself.

To remove the agent, use the panel or run `trassa-agent uninstall` on the server. The agent stops its services and removes its files and user; the server keeps running without Trassa.

Updates are signed and rolled out in waves. If a new version fails to start, the agent goes back to the previous one. You can pin a version.

## Repository layout

| Path | Contents |
|---|---|
| [`proto/trassa/agent/v1/`](proto/trassa/agent/v1/) | The agent–panel channel contract (protobuf) |
| `cmd/trassa-agent`, `cmd/trassa-helper` | The two processes: unprivileged network process and root helper |
| `internal/channel`, `internal/identity`, `internal/enroll` | WSS channel, agent key, enrollment |
| `internal/helper`, `internal/helperrpc`, `internal/ops`, `internal/nonce` | Helper: socket with caller uid check, built-in operation list, signature, expiry and nonce checks |
| `internal/rollback`, `internal/autorollback` | Rollback points and timer-based auto-rollback via systemd |
| `internal/update`, `internal/uninstall`, `internal/redact`, `internal/sysinfo` | minisign-verified updates, uninstall, secret redaction in output, system facts |
| [`scripts/install.sh`](scripts/install.sh), [`packaging/systemd/`](packaging/systemd/) | Installer and service units |
| `test/stubpanel`, `scripts/ci-matrix.sh`, `tools/release-sign`, `scripts/release-gate.sh` | CI OS matrix against a stub panel, release signing and the pre-publish check |

Updates are downloaded by the network process; the helper never goes online, it only verifies the signature and checksums of what was downloaded and installs the binaries.

Build and checks: Go 1.26, `make tools`, then `make check` (protobuf codegen, `go vet`, staticcheck, tests in the regular build and with the internal `testops` tag, release binary check). The test operation `test.config_write` exists only in builds with the `testops` tag; `make release-check` verifies the release binary does not contain it. CI on every commit: the OS matrix (Ubuntu 22.04 and 24.04, Debian 12 and 13 on amd64 and arm64 in containers with systemd: install with the panel command, refusal on a tampered signature, coming online, `system.info`, reinstall, removal; the report is the `matrix-report-*` artifact) and a release build on two runners with a `sha256` comparison.

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

An unsigned release is never published: `scripts/release-gate.sh` checks the signature with the same code and keys as `install.sh`. Until the owner adds the keys the list is empty, and installation and updates deliberately refuse.

## Security

Found a vulnerability? Please do not open a public issue. Report it through a [private GitHub report](https://github.com/NogMeer/trassa-agent/security/advisories/new). See [SECURITY.md](SECURITY.md) for details.

## License

- The agent code is licensed under [GNU AGPL-3.0](LICENSE). You are free to use, study and modify it. If you distribute a modified version or make it available over a network, you must release its source under the same terms.
- The protocol schema in [`proto/`](proto/) is licensed under [Apache-2.0](proto/LICENSE), so protocol clients can be generated without restrictions.

**Trademark.** The licenses grant rights to the code, not to the name. "Trassa" and the Trassa logo may not be used for forks or third-party services in a way that makes them look like Trassa or endorsed by us. A fork must use a different name.

## Contributing

Until the agent is released we are not accepting code changes. Questions and design suggestions are welcome in issues.
