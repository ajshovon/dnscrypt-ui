# DNSCrypt UI

A GNOME / Libadwaita interface for **`dnscrypt-proxy`** on Fedora and other Linux distributions.

- **System DNS protection**: checks that every application actually resolves through dnscrypt-proxy (no leaks to DHCP/router DNS), and fixes it in one click.
- **Resolvers**: pick encrypted DoH / DNSCrypt upstreams from the list dnscrypt-proxy itself loads, see why a server would be skipped (no-log, no-filter, DNSSEC, protocol), or add your own `sdns://` stamp.
- **Domain Rules (split DNS)**: send a domain and its subdomains to a specific DNS server, e.g. `lan → $DHCP` or `corp.example → 10.0.0.53`.
- **Query Log**: live view of dnscrypt-proxy's query log with blocked/error highlighting.
- **Safe apply**: changes are validated with `dnscrypt-proxy -check`, backed up, and rolled back automatically if the service does not come up.

## Install

```bash
sudo dnf install dnscrypt-proxy
cd dns-crypt-ui
./install.sh          # user install + root-owned helper and polkit action (asks for sudo)
./install.sh --user-only   # skip the helper (the app then runs it from this folder)
```

Run without installing: `./run.sh`. Run the tests: `python3 -m unittest discover -s tests -v`.

## Routing system DNS through dnscrypt-proxy

Installing dnscrypt-proxy does not make applications use it. On Fedora, `/etc/resolv.conf` points at systemd-resolved, which uses the DNS servers your network hands out via DHCP. The Dashboard shows whether queries leak and offers **Fix**, which does the equivalent of:

```ini
# /etc/systemd/resolved.conf.d/zz-dnscrypt-ui.conf
[Resolve]
DNS=127.0.0.1
Domains=~.
FallbackDNS=
DNSOverTLS=no
DNSStubListener=yes

# /etc/NetworkManager/conf.d/90-dnscrypt-ui.conf
[main]
dns=none
```

It also makes `/etc/resolv.conf` a link to the systemd-resolved stub, then reloads NetworkManager and restarts systemd-resolved. Without the NetworkManager part, systemd-resolved keeps sending queries to the DHCP server in parallel, and they leak unencrypted.

**Undo** on the Dashboard removes both files.

> Older versions of this README said to set `DNSStubListener=no`. That left the router's DNS in `/etc/resolv.conf` and leaked queries. **Fix** removes that old `dnscrypt.conf` drop-in.

## How changes are applied

The app never runs code as root from your home directory or `/tmp` once the helper is installed:

1. The new `dnscrypt-proxy.toml` and `forwarding-rules.txt` are sent to `/usr/local/libexec/dnscrypt-ui-helper` over stdin, through `pkexec` (polkit action `io.github.shovon.DNSCryptUI.helper`).
2. The helper only writes files directly inside `/etc/dnscrypt-proxy`, keeps the last 10 versions in `/etc/dnscrypt-proxy/.dnscrypt-ui-backup/`, and runs `dnscrypt-proxy -check`.
3. It restarts the service and restores the previous files if it does not stay up.

Starting and stopping the service uses systemd's D-Bus API and its own polkit prompt.

Editing keeps your comments and every setting the UI does not manage. Only changed keys are rewritten.

## Limitations

Domain Rules use dnscrypt-proxy's `forwarding_rules`, which can only forward to **plain DNS** servers (`IP[:port]`, `$DHCP`, `$BOOTSTRAP`). You cannot send one domain to a different *encrypted* resolver, which YogaDNS can do. The app warns when a rule sends queries to a public server unencrypted.

## Project structure

```text
dns-crypt-ui/
├── bin/dnscrypt-ui                 # launcher
├── helper/dnscrypt-ui-helper       # privileged helper (standalone, runs as root)
├── data/                           # desktop entry, icon, polkit policy
├── dnscrypt_ui/
│   ├── app.py                      # Adw.Application and main window
│   ├── backend/
│   │   ├── config_manager.py       # dnscrypt-proxy.toml + forwarding-rules.txt model
│   │   ├── tomledit.py             # comment-preserving TOML editor
│   │   ├── validate.py             # input validation
│   │   ├── resolver_db.py          # resolver catalog from `dnscrypt-proxy -list-all -json`
│   │   ├── service_manager.py      # systemd, helper, leak check, DNS tests
│   │   └── query_monitor.py        # query log tailer
│   └── views/                      # Dashboard, Domain Rules, Resolvers, Query Log, Settings
└── tests/test_backend.py
```
