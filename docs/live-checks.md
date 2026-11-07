# Live checks: the jury runbook

The jury session is 15 minutes: 7 minutes of pitch, then 8 minutes of live checks, **in this order** (brief, "Live checks you must be ready to show"). Each check below has the command, what a pass looks like, and what to do if it misbehaves.

The outputs are copied from real runs on `main` (7 Nov). Checks 1, 4, 5 and 6 used the organizers' Validation Set; check 2 used `V2_smart_home.xml`. **On the day, run everything on the scanner laptop on `RSH-dork_unit`, checked out at the `final` tag.**

`bilet` and `tool` are the same command (#101). Use whichever is installed.

## Before the session (5 minutes)

```bash
git checkout final && make setup              # the exact build that made the upload
tool detect --lang en                         # one private network, a /24 or smaller
tool serve &                                  # http://127.0.0.1:8000, open it in the browser
```

- **Have these ready:** the Test Set folder, the uploaded `findings.csv` / `scores.csv`, the lab before/after captures (`tests/fixtures/lab/`, #34), and gitleaks installed (`brew install gitleaks` / `apt install gitleaks`).
- **Close everything that isn't the hotspot:** cable, venue Wi-Fi, VPN.

## 1. Re-run one Test Set file: it must match the upload

The jury picks a file. Re-run it alone and compare with the upload. **If this differs, Test Set accuracy (30%) scores 0.**

```bash
mkdir -p /tmp/one && cp <TestSet>/<FILE>.xml /tmp/one/
tool analyze /tmp/one --out /tmp/rerun --lang en
grep '^<FILE>.xml,' <upload>/findings.csv | cmp - <(grep '^<FILE>.xml,' /tmp/rerun/findings.csv) && echo SAME
grep '^<FILE>.xml,' <upload>/scores.csv /tmp/rerun/scores.csv
```

Real run (V4 from the Validation Set): `1 files, 6 findings, 0 unreadable`, the rows are identical, and the score is `V4_legacy.xml,25` in both.

**If it differs:** you're not on the `final` build (`git describe --tags`), or the upload came from another machine. Say so honestly; don't edit files.

## 2. Hands-on: "Which device is the most dangerous, and what should I do first?"

A jury member uses the UI without help. Open the scan they'll ask about, e.g. a Test Set file through **"Open a scan file"** on the home screen, or `tool serve --result <file>.json` (`tool analyze <folder> --json` writes those).

What the home screen shows (V2):

> **Your network score: 40 out of 100. Network at risk.**
> **Most dangerous device:** Camera at 192.168.1.40 (ipcam), 30 risk points.
> **Do this first:** Camera video can be watched on your network: open the camera's app or settings page.
> *Why it matters:* This device sends a live video stream that other devices on your network can open…

The language switch (Română / English) is at the top. Hands off: let them find it.

## 3. Explanations and fixes for three findings the jury names

Open **`/risks`** (linked from every page). All 15 catalog codes are there, each with its plain RO/EN explanation, 1–5 fix steps and CIS/OWASP references, so a code that isn't in the scan on screen works too. Each finding on the home screen links to its entry (`/risks#CAMERA_STREAM_EXPOSED`).

## 4. Guardrail: try a public IP and the venue network; it must refuse

```bash
tool scan 8.8.8.8 --confirm --lang en
tool scan <venue range, e.g. 192.168.1.0/24> --confirm --lang en
```

Real run:

```
The address 8.8.8.8 is on the internet, not in your home network. The tool only checks your own network.
(PUBLIC_ADDRESS)                                                             exit=3
The address 192.168.1.0/24 is not part of the network this computer is connected to. The tool only checks the network it is connected to.
(OUTSIDE_ALLOWLIST)                                                          exit=3
```

Also good to show:
- `tool scan` with no `--confirm` explains what it *would* scan (`CONFIRM_REQUIRED`).
- `100.64.0.1` (the mobile operator's range), `127.0.0.1`, `router.lan` and `10.0.0.0/16` are all refused, each with its own reason.

## 5. Open an unreadable file: a clear error, no crash

```bash
mkdir -p /tmp/broken && cp tests/fixtures/validation/V7_broken.xml /tmp/broken/
tool analyze /tmp/broken --out /tmp/bo --lang en ; cat /tmp/bo/scores.csv
```

Real run:

```
V7_broken.xml: This file is damaged or incomplete, so it can't be read. (NOT_XML)
1 files, 0 findings, 1 unreadable -> /tmp/bo/findings.csv, /tmp/bo/scores.csv
file,network_score
V7_broken.xml,ERROR
```

The same file through the UI's "Open a scan file" shows the RO/EN error on the page, never a 500. Spares for the same check: `tests/fixtures/traps/T07_xxe_external_entity.xml` (UNSAFE_XML), `T09_empty.xml`, `T10_not_nmap.xml`.

## 6. Before/after from our own lab: the score improves

The lab captures (#34) are the real ones. Load them into the history, then open **`/history`**:

```bash
tool analyze tests/fixtures/lab --out /tmp/lab --save --lang en
```

Real run with the Validation Set's own pair (V6a → V6b, a stand-in until #34's captures are in):
- The command prints `saved 2 scans to the local history` and the alert *"The device at 192.168.1.1 has a new service turned on (port 443/tcp)…"*.
- `/history` shows **"score went up from 60 to 100"**, the trend chart, and the compare view with the 3 resolved findings (HTTP admin `.1:80`, UPnP `.1:1900`, telnet `.30:23`).

**Live version, if time allows (MASTERPLAN §4.3):**
1. `tool scan --confirm`.
2. `sudo labctl fix telnet` on the camera Pi (its LED turns green).
3. `tool scan --confirm` again.
4. The home screen and `/history` show the score climbing.

## 7. No secrets in the repository

```bash
gitleaks detect --source . --redact --verbose
```

A pass ends with `no leaks found`. CI runs the same scan on every push and PR (the `gitleaks (NFR-01)` check), so the PR page is a backup if gitleaks isn't installed. The API key is only ever in the environment (`.env` is git-ignored; `.env.example` holds empty placeholders).

## Still to do on the day (needs a human on the hotspot)

- Run all seven once on the scanner laptop at the `final` tag, and time the session.
- Check 6 with the real lab captures from #34 (score 25 → 55 for L1 → L2).
- `tool scan --confirm` on the full hotspot: record how long it takes (NFR-07: a /24 in under 5 minutes) and check that the laptop's own IP doesn't appear as UNKNOWN_DEVICE.
