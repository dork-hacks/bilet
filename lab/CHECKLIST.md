# Hotspot run: verify the Pis and save the lab captures (#34)

For the **human** on the scanner laptop. Agents never scan (WORKFLOW.md §10). Only scan our
own hotspot: `lab/verify` refuses anything else, but you are the last check.
Tick each box in the #34 PR or issue as you go. Commands run from the repo root.

## Before the event (home Wi-Fi)

- [ ] Each Pi 4 is set up with its role (README "Setting up a Pi"; two Pis since #128):
      `sudo lab/setup.sh camera` on pi2, `sudo lab/setup.sh hub --with-packages` on pi3, and
      `sudo lab/setup.sh server --with-packages` on the optional third device. Packages
      download here, not over the hotspot.
- [ ] The laptop has nmap (`apt install nmap` / `brew install nmap`), Python 3.11+ and
      `make setup` done, so `.venv/bin/python` and `.venv/bin/tool` exist.

## 1. Network

- [ ] The Pi 5 (OpenWrt, MASTERPLAN §4.2) runs the hotspot **`RSH-dork_unit`**: WPA2 or
      WPA3, a strong password, **2.4 GHz** band. Its uplink (team phone over USB, or
      Ethernet) is a second interface, not the access point's radio.
- [ ] The scanner laptop joins `RSH-dork_unit` **and nothing else**: Ethernet unplugged,
      venue Wi-Fi forgotten, VPN off. `.venv/bin/tool detect --lang en` must show a single
      network with a private subnet no larger than a /24.
- [ ] The camera and hub Pis are on the hotspot. Read their IPs from the Pi 5's DHCP leases
      (LuCI: Status → Overview, or `cat /tmp/dhcp.leases` on the Pi 5). Leave `SRV` empty
      until the optional third device is on; the loops below then skip it:
      ```bash
      CAM=<camera IP>; HUB=<hub IP>; SRV=; PI=<your SSH user>
      ROLES="--camera $CAM --hub $HUB${SRV:+ --server $SRV}"
      ```
- [ ] **Client isolation test:** `ping -c 3 $CAM` and `ping -c 3 $HUB` from the laptop, and
      `ssh $PI@$CAM ping -c 3 $HUB` between the two Pis. If pings fail, the
      hotspot isolates clients: on the Pi 5, turn off **Isolate Clients** for the
      `RSH-dork_unit` wireless network (LuCI: Network → Wireless → Edit → Advanced Settings).

## 2. The Pis

- [ ] The hub has been rebooted after `setup.sh`, so its random MAC and "no hostname" are on.
      Its IP may have changed: re-read it and update `$HUB`.
- [ ] On every Pi: `sudo labctl reset` (default lab), then save what is on:
      ```bash
      mkdir -p lab/captures
      for h in $CAM $SRV $HUB; do ssh $PI@$h /usr/local/sbin/labctl status; done > lab/captures/status_1.txt
      ```
      The LEDs blink red on both.

## 3. Capture 1: the default lab (score 25)

- [ ] Dry run, nothing is scanned: `python3 -I lab/verify $ROLES --print-only`.
      Check the "Scope OK" line and the nmap command (only the Pis' IPs, lab ports only).
- [ ] Scan and check: `python3 -I lab/verify $ROLES --status-file lab/captures/status_1.txt --confirm`.
      sudo asks for your password for nmap only. Every row must be **PASS**, exit code 0.
      `method=table` on jetdirect and upnp is expected. On a FAIL, read the NOTE column,
      fix the Pi, delete the failed capture and scan again.
- [ ] Sanitise it into a fixture:
      ```bash
      .venv/bin/python -I lab/sanitize lab/captures/scan_<time>.xml L1_default.xml $ROLES \
        --status-file lab/captures/status_1.txt --expected
      ```
      It must say `engine parser: OK, 2 hosts` and `score 25` (8 findings, 7 types).

## 4. Capture 2: after two fixes (score 55)

- [ ] On the camera Pi (`ssh $PI@$CAM`): `sudo labctl fix telnet` and `sudo labctl fix http`.
      Its LED still blinks: the FTP server is on until `fix ftp` (score 85, LED green).
- [ ] `for h in $CAM $SRV $HUB; do ssh $PI@$h /usr/local/sbin/labctl status; done > lab/captures/status_2.txt`
- [ ] `python3 -I lab/verify $ROLES --status-file lab/captures/status_2.txt --confirm`: all PASS.
- [ ] `.venv/bin/python -I lab/sanitize lab/captures/scan_<time>.xml L2_after_fix.xml $ROLES --status-file lab/captures/status_2.txt --expected`:
      score 55. L1 and L2 are the before/after pair (2 findings fixed).

## 5. Capture 3: the other toggles (score 20)

This covers the codes captures 1 and 2 don't: CAMERA_STREAM, DB, SMB, UPNP, SNMP, PRINTER.
DB and SMB live on the optional third device, so set `SRV` and `ROLES` again with it first.
Without it, the score is 50 and DB_EXPOSED / SMB_EXPOSED aren't covered.

- [ ] Over SSH on each Pi. Camera: `sudo labctl fix ftp`, `sudo labctl break rtsp`.
      Server: `sudo labctl break redis`, `sudo labctl break smb`.
      Hub: `sudo labctl fix mqtt`, `sudo labctl break ssdp`, `sudo labctl break snmp`,
      `sudo labctl break jetdirect`.
- [ ] `for h in $CAM $SRV $HUB; do ssh $PI@$h /usr/local/sbin/labctl status; done > lab/captures/status_3.txt`
- [ ] `python3 -I lab/verify $ROLES --status-file lab/captures/status_3.txt --confirm`: all PASS.
      If snmp says `open|filtered`, note it in #34 (README "Not verified yet").
- [ ] `.venv/bin/python -I lab/sanitize lab/captures/scan_<time>.xml L3_toggles.xml $ROLES --status-file lab/captures/status_3.txt --expected`:
      score 20.
- [ ] `sudo labctl reset` on every Pi. When the event is over: `sudo lab/setup.sh remove`.

## 5b. The router adds nothing (#128)

- [ ] With the default lab back on (`sudo labctl reset` on every Pi), run the tool's own
      scan of the whole hotspot: `.venv/bin/tool scan --confirm`. The Pi 5 router may show
      SSH_OPEN (0 points) and nothing else, and the score must still be 25. LuCI on 80/443
      is fine only if its page title has none of the admin words. If the router adds
      points, say so in #128 before anyone records the demo.
      Teammates' laptops on the hotspot are scanned too and can add findings of their own,
      so for this check only the scanner laptop, the Pis and the router should be on it.

## 6. Hand-check and commit

- [ ] Read `tests/fixtures/lab/expected_findings.csv` row by row against the verify tables
      (they come from `services.tsv` and the toggles, not from the engine) and
      `expected_scores.csv` (L1 25, L2 55, L3 20).
- [ ] Compare with the engine:
      ```bash
      .venv/bin/tool analyze tests/fixtures/lab --out /tmp/lab-out
      diff tests/fixtures/lab/expected_findings.csv /tmp/lab-out/findings.csv
      diff tests/fixtures/lab/expected_scores.csv /tmp/lab-out/scores.csv
      ```
      If they differ, don't copy the engine's output: find out who is wrong and say so in #34.
- [ ] Privacy: every MAC in the fixtures ends in `00:00:01` (camera), `00:00:02` (server)
      or `00:00:03` (hub)
      (`grep -ho 'addr="[0-9A-F:]*" addrtype="mac"' tests/fixtures/lab/*.xml | sort -u`),
      and no real hostname, name or home path is left (`grep -i` for them). Run gitleaks.
- [ ] Commit the three XML files and both expected CSVs on a branch, open a PR that
      closes #34, and paste the three verify summaries (the PASS lines) into it.
      `lab/captures/` stays out of git.
- [ ] Optional, once `tool scan` exists: scan the whole hotspot subnet with it and check that
      the laptop's own IP doesn't come out as UNKNOWN_DEVICE. The Pi 5 router shows up in
      that scan too, and its findings count in the score: it should show at most `SSH_OPEN`
      (key-only) and no HTTP_ADMIN_CLEARTEXT. Lock down LuCI (HTTPS only, or LAN-side
      access off) before the jury run if it does.
