# Hotspot lab: "house in a box"

Three Raspberry Pi 4s, each playing a household device with **simulated** weak services
(MASTERPLAN §4.1). Until the Pis arrive, or if the hotspot isolates its clients, the same
fake services run as three Docker containers (brief setup D).

**Simulate, do not expose.** Every weak service is a fake banner (`fakes/fakesvc.py`) or a
real daemon locked down so it grants nothing. No login ever works, client input is never
executed, stored or logged, and every connection has a byte limit, timeouts and a
connection cap. Only scan the team hotspot.

## Roles and the default lab

| Pi | Role | Weak services (default **on**, others are toggles) | Catalog codes |
|---|---|---|---|
| Pi 4 #1 | `camera` (IP camera) | **telnet** on 2323 (BusyBox), **http** "Camera Login" on 80, rtsp on 554 | TELNET_OPEN, HTTP_ADMIN_CLEARTEXT, CAMERA_STREAM_EXPOSED |
| Pi 4 #2 | `server` (old office server) | **ftp** `vsFTPd 2.3.4` on 21, redis on 6379, smb (Samba, no shares) | FTP_CLEARTEXT + OUTDATED_SERVICE, DB_EXPOSED, SMB_EXPOSED |
| Pi 4 #3 | `hub` ("mystery" smart hub) | **mqtt** on 1883, **random MAC + no hostname**, ssdp on UDP 1900, snmp on UDP 161, jetdirect on 9100 | MQTT_EXPOSED, UNKNOWN_DEVICE, UPNP_EXPOSED, SNMP_EXPOSED, PRINTER_RAW_EXPOSED |

Every Pi also runs key-only SSH for administration: `SSH_OPEN`, 0 points.
`services.tsv` is the single source of truth for this table.

**Default lab = 75 points, score 25, 7 finding types** (MASTERPLAN §4.1):

| Device | Expected findings |
|---|---|
| camera | TELNET_OPEN 2323 (20), HTTP_ADMIN_CLEARTEXT 80 (10), SSH_OPEN 22 (0) |
| server | FTP_CLEARTEXT 21 (10), OUTDATED_SERVICE 21 (20), SSH_OPEN 22 (0) |
| hub | MQTT_EXPOSED 1883 (10), UNKNOWN_DEVICE, empty port (5), SSH_OPEN 22 (0) |

## Setting up a Pi

Before the event, on home Wi-Fi (hotspot data is limited):

1. Flash Raspberry Pi OS Lite 64-bit (bookworm), enable SSH with your public key in Raspberry Pi Imager.
2. Join the Pi to the team hotspot (`RSH-<team-number>`) and to nothing else.
3. Copy this repo onto the Pi and install its role:

```bash
git clone <repo> && cd <repo>
sudo lab/setup.sh camera                   # Pi 4 #1
sudo lab/setup.sh server --with-packages   # Pi 4 #2 (installs samba for the smb toggle)
sudo lab/setup.sh hub --with-packages      # Pi 4 #3 (installs snmpd for the snmp toggle)
```

For the hub, reboot afterwards so the random MAC and "no hostname" take effect. Its IP may
change; find it in the hotspot's client list. The MAC is `stable` (locally administered,
same after reboots), so history doesn't see a "new device" after every restart.

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
on the camera, its LED turns green → rescan (score 55). Then power on another Pi for the
"new device" alert (FR-13).

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

## Docker fallback (setup D)

```bash
docker compose -f lab/docker/compose.yaml up -d            # camera .11, server .12, hub .13 on 10.77.0.0/24
docker compose -f lab/docker/compose.yaml --profile scan run --rm scanner \
  -sS -sU -sV --script http-title --max-rate 100 \
  -p T:21,22,23,80,554,1883,2323,6379,9100,U:161,1900 -oX /out/scan_01.xml 10.77.0.11-13
docker compose -f lab/docker/compose.yaml down
```

Scans land in `lab/docker/out/` (git-ignored). Choose the services per device with
`CAMERA_SERVICES`, `SERVER_SERVICES` and `HUB_SERVICES`, for example
`CAMERA_SERVICES="http" docker compose -f lab/docker/compose.yaml up -d camera` is the
camera with telnet fixed. Differences from the Pis: no SSH, Samba or SNMP, and Docker
gives every container a random MAC with no vendor, so identity-based findings
(UNKNOWN_DEVICE) don't match the Pi lab.

## What nmap -sV makes of the fakes

Checked with nmap 7.95 (`instrumentisto/nmap:7.95`) against the Docker lab:

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

## Tests

```bash
python3 -m unittest discover -s lab/tests
```

## Not verified yet

- On a real Raspberry Pi: `setup.sh`, `labctl`, the LEDs, Samba, snmpd and the hub identity
  (random MAC, no DHCP hostname) are written for Raspberry Pi OS bookworm but haven't run on
  one yet. The systemd units pass `systemd-analyze verify`.
- SNMP: whether nmap marks the locked-down snmpd as `open` (it should, via the SNMPv3
  engine-discovery reply) still needs a scan.
- The scanner laptop scanning itself shows up without a MAC; the analyser must not turn
  that into a false UNKNOWN_DEVICE (#34).
