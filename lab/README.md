# Hotspot lab: "house in a box"

Two Raspberry Pi 4s on the team hotspot, each playing a household device with
**simulated** weak services, plus an optional third device that joins later (MASTERPLAN §4.1,
#128). The scanner is still a laptop (the brief
requires it); only the targets are Pis.

**Simulate, do not expose.** Every weak service is a fake banner (`fakes/fakesvc.py`) or a
real daemon locked down so it grants nothing. No login works, except the camera's settings
page (below), whose password is the public device ID on the Pi's label and which only holds
switches for this Pi's simulated services. Client input is never executed, stored or logged,
and every connection has a byte limit, timeouts and a connection cap. Only scan the team
hotspot.

## Roles and the default lab

| Pi | Role | Weak services (default **on**, others are toggles) | Catalog codes |
|---|---|---|---|
| pi2 | `camera` (IP camera that uploads clips over FTP) | **telnet** on 2323 (BusyBox), **http** "Camera Login" on 80, **ftp** `vsFTPd 2.3.4` on 21, rtsp on 554 | TELNET_OPEN, HTTP_ADMIN_CLEARTEXT, FTP_CLEARTEXT + OUTDATED_SERVICE, CAMERA_STREAM_EXPOSED |
| pi3 | `hub` ("mystery" smart hub) | **mqtt** on 1883, **random MAC + no hostname**, ssdp on UDP 1900, snmp on UDP 161, jetdirect on 9100 | MQTT_EXPOSED, UNKNOWN_DEVICE, UPNP_EXPOSED, SNMP_EXPOSED, PRINTER_RAW_EXPOSED |
| optional third device | `server` (old office server) | nothing on by default; redis on 6379, smb (Samba, no shares) | DB_EXPOSED, SMB_EXPOSED |

Every Pi also runs key-only SSH for administration: `SSH_OPEN`, 0 points.
`services.tsv` is the single source of truth for this table.

**Default lab = two Pis, 75 points, score 25, 7 finding types** (MASTERPLAN §4.1). The
optional `server` adds 0 points until one of its toggles is switched on:

| Device | Expected findings |
|---|---|
| camera | FTP_CLEARTEXT 21 (10), OUTDATED_SERVICE 21 (20), SSH_OPEN 22 (0), HTTP_ADMIN_CLEARTEXT 80 (10), TELNET_OPEN 2323 (20) |
| hub | MQTT_EXPOSED 1883 (10), UNKNOWN_DEVICE, empty port (5), SSH_OPEN 22 (0) |
| server (optional) | SSH_OPEN 22 (0) |

## Minimum lab (brief, ready by hour 3)

| # | The brief asks for | How we do it |
|---|---|---|
| 1 | Gateway: a team phone hotspot `RSH-<team>`, WPA2/WPA3, strong password, data limit | `RSH-dork_unit` on 2.4 GHz. The Pi 5 serves it (mentors said a phone isn't required, #64); a team phone hotspot is the fallback. |
| 2 | Scanner: one laptop on the hotspot and **nothing else** | Ethernet unplugged, venue Wi-Fi forgotten, VPNs (Tailscale too) off. `tool detect` shows one network. |
| 3 | At least 3 target devices or services | Two Pi 4s with 7 weak services between them, plus the optional third device. |
| 4 | At least 5 finding types | The default lab has 7 (table below); capture 3 adds the other 6 Pi codes. |
| 5 | Every scan saved as nmap XML | `nmap -sS -sU -sV -oX`, via `lab/verify` (#34) or `tool scan` (#20). |
| 6 | Before/after: fix at least 2 findings, rescan, keep both files | `labctl fix telnet` + `labctl fix http` on the camera: score 25 → 55. |

Check early that the laptop and the Pis can ping each other: some phones isolate hotspot
clients. The step-by-step run is in `CHECKLIST.md` (#34).

## Setting up a Pi

Before the event, on home Wi-Fi (hotspot data is limited). Each step runs on a Linux laptop
with the SD card in a reader; the scripts refuse anything that isn't a removable card.

1. Flash Raspberry Pi OS Lite 64-bit with hostname, user, SSH keys and SSH on (cloud-init).
   The image is downloaded and checksummed into `out/pi-images/` if it isn't there:
   ```bash
   sudo lab/flash_pi.sh /dev/sdX pi2
   ```
2. Join it to the team hotspot (`RSH-dork_unit`) and to nothing else. This writes a
   NetworkManager profile, sets the Wi-Fi country (RO) and keeps logs across reboots:
   ```bash
   sudo lab/pi_wifi_nm.sh /dev/sdX RSH-dork_unit
   ```
   (`lab/pi_wifi.sh` does the same through cloud-init, but only before the first boot.)
3. Boot the Pi, SSH in, copy this repo onto it and install its role:

```bash
git clone <repo> && cd <repo>
sudo lab/setup.sh camera                   # pi2
sudo lab/setup.sh hub --with-packages      # pi3 (installs snmpd for the snmp toggle)
sudo lab/setup.sh server --with-packages   # optional third device (samba for the smb toggle)
```

For the hub, reboot afterwards so the random MAC and "no hostname" take effect. Its IP may
change; find it in the hotspot's client list. The MAC is `stable` (locally administered,
same after reboots), so history doesn't see a "new device" after every restart.

**Or skip the SSH step:** put the role on the card from the laptop, without sudo (it only
writes the boot partition), then boot the Pi. It installs the role by itself once it's on
the hotspot, and the hub reboots once more for its new identity:

```bash
lab/card_role.sh /dev/sdX hub --on ssdp,jetdirect   # pi3: default hub + SSDP and JetDirect
lab/card_role.sh /dev/sdX camera                    # pi2
```

`--on` turns on extra toggles from `services.tsv` (`sudo labctl reset` on the Pi goes back
to the default lab). Progress on the Pi: `journalctl -u lab-install`.

`sudo lab/setup.sh remove` switches everything off and undoes the install.

## Fixing and breaking (the before/after demo)

```bash
labctl status              # what's on, with codes and points
sudo labctl fix telnet     # turn one weak service off
sudo labctl break telnet   # turn it back on
sudo labctl reset          # back to the default lab
labctl list                # every service of every role
```

The on-board LEDs show the state: **blinking red** = at least one weak service is on,
**steady green** = everything on this Pi is fixed. `sudo labctl leds-restore` gives the LEDs
back to the system.

Demo (MASTERPLAN §4.3): scan (score 25) → `sudo labctl fix telnet` and `sudo labctl fix http`
on the camera → rescan (score 55). `sudo labctl fix ftp` too and its LED turns green (85).
Then power on the optional third device for the "new device" alert (FR-13): no score change,
and `sudo labctl break redis` on it gives "new open port".

### From the device's own settings page (#144)

A juror can follow the tool's own fix steps on the camera: open `http://<camera-ip>/`
("Camera Login"), sign in as `admin` with the **device ID on the Pi's label**, and flip the
switch the steps name ("Telnet / remote access", "Video stream (RTSP)", …). The rescan then
shows the finding resolved.

- `setup.sh` prints the device ID at the end (and keeps it in `/etc/lab/device-id`). Write it
  on a sticker on the Pi. It is derived from `/etc/machine-id`, so it stays the same when you
  reinstall or change the role. It is public on purpose, like a router's sticker password: not
  the MAC, not anyone's real password.
- The root page and its title stay exactly "Camera Login", so HTTP_ADMIN_CLEARTEXT still
  matches; the settings live on `/settings`, which `http-title` never fetches.
- The page can't call sudo (it runs sandboxed, with `NoNewPrivileges`). It writes one line to
  `lab-switch.socket` (`/run/lab-switch.sock`, root:lab-web, mode 0660), and systemd starts
  `switchd.py` as root for that one request. It accepts only `status`, `fix SERVICE` or
  `break SERVICE` for a service of this Pi's role, and runs `labctl` with a fixed argv, never a
  shell. Everything else gets `refused`. Only the HTTP fake is in the `lab-web` group.
- Sessions are random, `HttpOnly`, `SameSite=Strict`, in memory only and expire after 15 min.
  Every switch carries a CSRF token. A wrong password waits 1 s and shows the same page as
  before.

## How the fakes run

On a Pi, each fake is a systemd instance `lab-fake@<service>` running `fakesvc.py` as a
throwaway user (`DynamicUser`), with only `CAP_NET_BIND_SERVICE` and a strict sandbox
(`systemd-analyze security`: exposure 1.5, "OK"). The real daemons are configured to grant
nothing: Samba has no shares and no guest access, snmpd has no communities and no users.

You can also run the fakes by hand on any machine with Python 3.11+:

```bash
python3 -I lab/fakes/fakesvc.py telnet http --bind 0.0.0.0
python3 -I lab/fakes/fakesvc.py ftp --bind 127.0.0.1 --port 2121
```

## What nmap -sV makes of the fakes

Checked during development with nmap 7.95 against the fakes running locally in containers
(not on the hotspot). `lab/verify` repeats the check against the Pis on the hotspot (next
section):

| Port | Service name | Product / version | `method` |
|---|---|---|---|
| 2323/tcp | telnet | | probed |
| 80/tcp | http, title "Camera Login" | lighttpd 1.4.59 | probed |
| 554/tcp | rtsp | | probed |
| 21/tcp | ftp | vsftpd 2.3.4 | probed |
| 6379/tcp | redis | Redis key-value store | probed |
| 1883/tcp | mqtt | | probed |
| 9100/tcp | jetdirect | | **table** |
| 1900/udp | upnp | | **table** |

The two `table` results are nmap's behaviour, not something a better fake can fix, so real
devices look the same:

- nmap never probes TCP 9100–9107 during version detection (`Exclude T:9100-9107` in
  `nmap-service-probes`), so it doesn't print junk on real printers.
- nmap's UDP `UPNP_MSEARCH` probe has no match lines, so a 1900/udp answer is always named
  from the port table.

This matters for the `method="table"` question in #8: if table-named services didn't count,
PRINTER_RAW_EXPOSED and UPNP_EXPOSED could never appear in a real scan.

Redis answers `-ERR operation not permitted` (older Redis with a password set) because
nmap recognises that reply; the newer `-NOAUTH` reply is only named from the port table.

## Verifying the Pis and saving captures (#34)

[`CHECKLIST.md`](CHECKLIST.md) is the step-by-step run on the hotspot. Only a human runs it,
on the scanner laptop; agents never scan.

```bash
lab/verify --camera IP --server IP --hub IP --confirm      # guarded sudo nmap, then the check
lab/verify --camera IP --server IP --hub IP --xml FILE     # check a capture, no scan
lab/sanitize lab/captures/scan_X.xml L1_default.xml --camera IP --server IP --hub IP
```

- **[`verify`](verify)** refuses anything but private IPs inside the laptop's own subnet
  (no 100.64.0.0/10, no public IPs, nothing larger than a /24, the laptop on one network
  only) and needs `--confirm`. It runs as your user; only the nmap subprocess gets `sudo`.
  It scans just the lab ports (TCP 21,22,80,139,445,554,1883,2323,6379,9100 and UDP
  161,1900) at `--max-rate 100` into `lab/captures/` (never committed), then prints a
  PASS/FAIL table: state, service name and `method` per port, toggled-off services that
  are still open, unexpected open ports, the hub's "no vendor, no hostname" identity and the
  scanner's own IP. Exit 0 = all passed, 1 = a check failed, 2 = refused or unreadable.
- **[`sanitize`](sanitize)** copies a capture to `tests/fixtures/lab/`: MACs keep their OUI
  (the vendor) and get `00:00:01` (camera), `00:00:02` (server) or `00:00:03` (hub) as the
  device half, real hostnames become the role name wherever they appear, and hosts that
  aren't lab Pis are removed. It runs the engine's parser on the result when it's importable
  and prints the expected `findings.csv` rows, worked out from `services.tsv` and the
  toggles rather than by the engine.
- Both are Python 3.11+ standard library ([`labcheck.py`](labcheck.py)); defusedxml is
  used when it's installed. Toggles default to the `default` column of `services.tsv`; pass
  `--on`/`--off SVC[,SVC]`, or `--status-file` with pasted `labctl status` output.

## Tests

```bash
python3 -m unittest discover -s lab/tests
```

## Not verified yet

- On a real Raspberry Pi: `setup.sh`, `labctl`, the LEDs, Samba, snmpd and the hub identity
  (random MAC, no DHCP hostname) are written for Raspberry Pi OS bookworm but haven't run on
  one yet. `flash_pi.sh` installs trixie (the current Lite image), so check them there.
  Seen on pi2 (trixie, 7 Nov, before #128): `card_role.sh` installed a role, `labctl status`
  works, the `lab-fake@ftp` fake listens on 21 and the PWR LED blinks.
  The systemd units pass `systemd-analyze verify`.
- The settings page switches (#144): offline tests only (`lab/tests/test_settings_page.py`,
  `test_switchd.py`). The socket unit, the `lab-web` group and the drop-in still need a run on
  a Pi: sign in, turn Telnet off, rescan.
- SNMP: whether nmap marks the locked-down snmpd as `open` (it should, via the SNMPv3
  engine-discovery reply) still needs a scan. `lab/verify` fails it with a hint if nmap
  says `open|filtered`.
- The scanner laptop scanning itself shows up without a MAC. `lab/verify` scans only the
  lab Pis and warns when a capture holds the laptop with open ports and no MAC, but the
  analyser must still not turn that into a false UNKNOWN_DEVICE in a whole-subnet scan (#34).
