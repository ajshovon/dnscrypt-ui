# DNSCrypt UI

A modern, native **GNOME / Libadwaita** graphical desktop interface for **`dnscrypt-proxy`** designed specifically for Fedora and Linux.

It brings the powerful, rule-based DNS features of **YogaDNS** to Linux:
- **YogaDNS-style Split-DNS Domain Routing**: Route specific domains and wildcards (`*.internal`, `*.lan`, `google.com`) to designated DNS servers (plain DNS, local gateway, or custom upstreams).
- **Encrypted Resolvers Catalog**: Browse, filter, and activate upstream **DNS-over-HTTPS (DoH)** and **DNSCrypt** servers (Quad9, Cloudflare, AdGuard, Google, Mullvad, NextDNS, etc.) with security/logging badges.
- **Live DNS Query Inspector**: Real-time traffic monitor with latency, domain filtering, and resolution/blocking status.
- **Service & Systemd Control**: Start, stop, and restart `dnscrypt-proxy` with a single PolicyKit prompt.
- **DNS Resolution Benchmark**: Built-in test query tool measuring latency through `127.0.0.1:53`.

---

## Screenshots & Highlights

- **Dashboard**: Live daemon status (active/stopped/PID), DNS query latency benchmark, and Fedora port 53 conflict detector.
- **Domain Rules (Split-DNS)**: YogaDNS rules tab equivalent. Add, edit, toggle, and delete rules like `*.work.internal 10.0.0.53` or `*.lan 192.168.1.1:53`.
- **Resolvers**: Filter by DoH, DNSCrypt, DNSSEC validation, and No-Log policies. Toggle servers on and off or add custom stamps.
- **Query Inspector**: Stream queries in real time, filter by keyword, pause/resume, and inspect blocked/allowed traffic.
- **One-Click Apply**: Batches config changes and restarts the system service with a single Polkit authentication popup.

---

## Getting Started on Fedora GNOME

### 1. Install `dnscrypt-proxy`
On Fedora, install the official package:
```bash
sudo dnf install dnscrypt-proxy
```

### 2. Handle Fedora's `systemd-resolved` Conflict
Fedora runs `systemd-resolved` on port `53` (`127.0.0.53:53`) by default. To let `dnscrypt-proxy` bind to `127.0.0.1:53` and receive system queries:

1. Create a drop-in configuration for `systemd-resolved`:
   ```bash
   sudo mkdir -p /etc/systemd/resolved.conf.d
   sudo tee /etc/systemd/resolved.conf.d/dnscrypt.conf << 'EOF'
   [Resolve]
   DNS=127.0.0.1
   DNSStubListener=no
   EOF
   ```
2. Restart `systemd-resolved`:
   ```bash
   sudo systemctl restart systemd-resolved
   ```
3. Enable and start `dnscrypt-proxy`:
   ```bash
   sudo systemctl enable --now dnscrypt-proxy
   ```

*(Note: The app's **Dashboard** and **Settings** tabs will detect this conflict automatically and provide this exact guide if needed).*

---

## Running & Installing DNSCrypt UI

### Run Directly
To launch without installing:
```bash
cd dns-crypt-ui
./run.sh
```

### Install into GNOME App Drawer
To install the application icon, desktop launcher, and binary into your user environment:
```bash
cd dns-crypt-ui
./install.sh
```
Once installed, press `Super` (Windows key) on GNOME and search for **DNSCrypt UI**!

---

## How Split-DNS Domain Routing Works (YogaDNS Replacement)

In the **Domain Rules** tab:
1. Click **Add Rule**.
2. Enter a domain or wildcard pattern (e.g., `*.lan`, `*.corp.internal`, or `reddit.com`).
3. Select a preset (e.g. `Local Router (192.168.1.1:53)`) or type custom IP addresses.
4. Click **Add Rule** and then click **Apply & Restart** in the top header bar.

Behind the scenes, this updates `/etc/dnscrypt-proxy/forwarding-rules.txt` and `/etc/dnscrypt-proxy/dnscrypt-proxy.toml` seamlessly.

---

## Project Structure

```text
dns-crypt-ui/
├── bin/
│   └── dnscrypt-ui             # Executable launcher
├── data/
│   ├── icons/
│   │   └── io.github.shovon.DNSCryptUI.svg  # Adwaita vector icon
│   └── io.github.shovon.DNSCryptUI.desktop  # Desktop entry
├── dnscrypt_ui/
│   ├── app.py                  # Main Adw.Application and Window
│   ├── backend/
│   │   ├── config_manager.py   # Surgical TOML & forwarding-rules parser
│   │   ├── query_monitor.py    # Real-time query.log streamer
│   │   ├── resolver_db.py      # Curated DoH & DNSCrypt catalog
│   │   └── service_manager.py  # Systemd & Polkit manager, DNS tester
│   └── views/
│       ├── status_view.py      # Service dashboard & DNS benchmark
│       ├── rules_view.py       # YogaDNS Split-DNS rules manager
│       ├── resolvers_view.py   # Upstream DoH/DNSCrypt resolvers
│       ├── query_log_view.py   # Live query inspector
│       └── settings_view.py    # Network & Fedora integration guide
├── install.sh                  # Installer for GNOME desktop integration
├── run.sh                      # Quick runner script
└── README.md
```
