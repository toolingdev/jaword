# jaword

Self-hosted secrets vault built so AI agents can create, rotate and manage
credentials **without ever seeing them**. One Rust codebase: server with web
UI, CLI, and MCP server.

- Status: v0.1.0
- Intended deployment: a small container, loopback listener, HTTPS via a private overlay network (e.g. `tailscale serve`)

## How agents rotate a password they never see

1. Agent calls `secret_rotate("home-lab/proxmox-root")` over MCP (or `jaword rotate`).
2. The vault generates the new value and stores it as a `pending` version.
3. The vault's rotation driver pushes it to the real system (SSH command or
   local program). The secret travels on the child's stdin only.
4. Driver succeeds: pending becomes `current`. Driver fails: old value stays
   current, new one is parked as `failed`.
5. The agent gets back `{rotated: true, version: N}`. No value.

The MCP server has no tool that returns a value, and the server refuses
`reveal` for any token with role `agent`, whatever its rules say.

## Layout

| Path | What |
|---|---|
| `crates/core` | Crypto, generator, access rules. No I/O, so it can compile to WASM (browser extension) and mobile bindings later. |
| `crates/server` | `jawordd`: HTTP API, encrypted SQLite store, audit log, rotation drivers, embedded web UI. |
| `crates/cli` | `jaword`: CLI and `jaword mcp` (stdio MCP server). |
| `deploy/` | systemd unit and container provisioning script. |
| `tests/pentest.py` | Black-box attack suite (81 checks). |

## Security design

**Keys.** Passphrase → Argon2id (128 MiB, t=3) → wraps a random 256-bit master
key. A recovery key wraps the same master key. HKDF derives separate keys for
wrapping, metadata, audit, tokens and row integrity. The master key exists
only in server memory; after every restart the vault is **sealed** until
someone enters the passphrase.

**Storage.** Every secret version gets its own random data key
(XChaCha20-Poly1305), wrapped by the master-derived key. Usernames, URLs,
notes and driver configs are encrypted too. Each ciphertext is bound to its
row, and rows carry a MAC, so editing the database directly (swapping two
secrets, rolling a version back, upgrading a token to admin, un-revoking a
token) is detected rather than obeyed. API tokens are stored only as HMACs.

**Access.** Tokens have a role (`admin`, `human`, `agent`) and path rules like
`home-lab/**=list,generate,rotate`. Capabilities: `list create update generate
rotate delete write reveal`. `write` (supplying a value yourself) is separate
from `update` (metadata), so an agent cannot set a secret to something it
knows. Default deny.

**Audit.** Every action, including denied ones, goes to an HMAC-chained log.
`jaword audit --verify` detects edited or deleted rows.

**Network.** Listens on loopback only; Tailscale serve provides HTTPS. Host
and Origin pinning, strict CSP, bearer-token auth with no cookies, 64 KiB body
cap, header timeout, connection cap. `init` is refused through any proxy.

**Process.** No `unsafe` in this repo. systemd sandbox (no capabilities,
read-only filesystem, no core dumps), container has swap disabled.

### Known limits (read these)

- This protects secrets from the **model's context and transcripts**. An agent
  with a root shell on a target machine can still read a secret where it lands
  on that machine.
- A saved admin token on a workstation is readable by anything running as you.
  Do admin work in the web UI; keep only a scoped token on disk.
- Someone who can write the database **and** roll the whole file back to an
  older copy is not detected (no external anchor yet). Ship the audit log off
  the box to close that.
- Request bodies holding a secret are not wiped from server memory after use.
- Not independently audited. The pen test here was done by the same author as
  the code.

## Daily use

```bash
jaword ls home-lab/
jaword new home-lab/gitea-admin --username admin        # value generated in vault
jaword rotate home-lab/proxmox-root                         # push new value via driver
jaword show home-lab/proxmox-root                           # metadata + history
jaword reveal home-lab/proxmox-root                         # humans only
jaword run -e PGPASSWORD=work/database -- psql ...    # inject into one command
jaword audit --verify
```

Every item has a **path** (its unique address, used by access rules and
agents, e.g. `home-lab/proxmox-root`) plus ordinary fields: name, website, username,
tags, notes.

### Changing a password

For most things (a utility company, a bank, a router) changing a password is
something you do on the site yourself. The vault's part:

1. **Change password** makes a new one: random characters, or 4 to 10 words.
2. Look at it, adjust it, **Keep** it. Nothing changes until you do.
3. Set it on the site. The old password stays in History.
4. If the site did not take it, **Use again** on the old version puts it back.

```bash
jaword gen home/router --words 5        # vault-side, value not shown
jaword restore home/router --version 2  # go back to an earlier version
```

Automatic rotation (below) is an optional extra for systems you administer.

### Folders

In the web UI people work with folders (Personal, Work, Business…) and item
names. Underneath, a folder is just a path prefix, so agents and access rules
keep stable addresses like `personal/banks/chase`.

```bash
jaword folder ls
jaword folder new business
jaword mv work/vpn business/vpn
jaword folder mv personal home             # rename, contents follow
jaword folder rm old --move-to archive     # keep the items
jaword folder rm old                       # delete folder and items
```

Moving needs `delete`+`list` at the source and `create` at the destination,
and is refused if it would let the mover read values it could not read before.

### Import and export

```bash
jaword import export.csv --prefix logins --dry-run   # preview
jaword import export.csv --prefix logins --remove-source
jaword export --out backup.csv                       # humans only, plain text
jaword export --out inventory.csv --metadata-only    # no values, fine for agents
```

Import reads CSV exports from 1Password, NordPass, Bitwarden, Chrome/Edge,
Firefox, LastPass and KeePassXC, from the web UI (**Import**), the CLI, or the
`secret_import_file` MCP tool. Folders in the export are kept, and logins
already in the vault are left alone, so an import can be run twice. One-time-code (TOTP) seeds are not imported yet.
Agents can run an import through the `secret_import_file` MCP tool: the tool
reads the file and returns only counts and paths. A full export is plain text
by nature, so it needs a token with `reveal`.

After a reboot of the container: open the web UI and enter the passphrase, or
run `jaword unseal`.

### Setting up rotation (admin only)

In the web UI, open an item and choose **Set up rotation**. Four steps, no
configuration files:

1. **How**: a user on a server (over SSH), or your own script.
2. **Where**: the server and the account whose password changes.
3. **Check**: the vault shows the server's fingerprint for you to confirm,
   gives you a short script to run once on that server, then tests the whole
   path without changing anything.
4. **Schedule**: only when asked, or every 30 days, 90 days or year.

The script in step 3 lets the vault's key run one helper on the server, and
that helper only sets passwords for accounts listed in
`/etc/jaword-rotate/accounts`. No shell, no other accounts.

Scheduled rotations run inside the vault and pause while it is sealed. A
failed one keeps the old password and is retried the next day.

From the CLI the same setup is a JSON file:

```json
{"type": "ssh", "host": "hypervisor-1", "user": "root",
 "command": "chpasswd", "stdin": "svc-backup:{{new}}\n", "every_days": 90}
```

```bash
jaword driver home-lab/backup-user --file setup.json
```

`{{new}}`, `{{old}}`, `{{username}}` are allowed in `stdin` only, never in the
command line. The vault uses its own SSH key and only host keys you have
confirmed (`/var/lib/jaword/.ssh`).

## Build, test, deploy

```bash
cargo test                                            # 40 unit tests
cargo build --release
cargo zigbuild --release --target x86_64-unknown-linux-musl   # static Linux
cargo audit                                           # dependency advisories
```

Pen test (throwaway instance only, it seals and tampers with the database):

```bash
python3 tests/pentest.py http://127.0.0.1:8212 init.json vault.db server.log
```

Server configuration is by environment: `JAWORD_DB`, `JAWORD_LISTEN`,
`JAWORD_ALLOWED_HOSTS` (see `deploy/jawordd.service`).

## Updates

The vault can update itself from signed GitHub releases, triggered from the
web UI (Updates page), `jaword update apply vX.Y.Z`, or the MCP tool
`vault_update_apply`.

- `scripts/release.sh vX.Y.Z` builds, signs each artifact with an SSH signing
  key (`ssh-keygen -Y sign`) and publishes a GitHub release.
- The vault process only drops a request file. A separate root helper
  (`deploy/jaword-updater`) downloads the release, verifies the signature
  against `/etc/jaword/release_signers`, refuses downgrades, installs, and
  rolls back if the new version does not start.
- The signature covers the version and file name, so an old release cannot be
  replayed as a new one.
- No signers file means updates are off.
- After an update the vault restarts **sealed**. A human unseals it.

Whoever holds the release signing key can replace the vault's code. Keep it
somewhere that needs a human approval per signature (for example the
1Password SSH agent), not in a plain file an agent can read.

## Not built yet

Browser extension, mobile apps, passkey login, auto-unseal, built-in drivers
for specific APIs (Proxmox, Gitea, Cloudflare), Windows service packaging
(the CLI already builds for Windows; the server's signal handling is
Unix-only).

## License

Apache-2.0. See [LICENSE](LICENSE).
