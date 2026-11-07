# Live checks: the jury runbook

The jury session is 15 minutes: 7 minutes of pitch, then 8 minutes of live checks, **in this order** (brief, "Live checks you must be ready to show"). Each check below has the command, what a pass looks like, and what to do if it misbehaves.

The outputs are copied from real runs on `main` (7 Nov). Checks 1, 4, 5 and 6 used the organizers' Validation Set; check 2 used `V2_smart_home.xml`. **On the day, run everything on the scanner laptop on `RSH-dork_unit`, checked out at the `final` tag.**

`bilet` and `tool` are the same command (#101). Use whichever is installed.

## Before the session (5 minutes)

```bash
git checkout final && make setup              # the exact build that made the upload
bilet detect --lang en                         # one private network, a /24 or smaller
bilet serve &                                  # http://127.0.0.1:8000, open it in the browser
```

- **Have these ready:** the Test Set folder, the uploaded `findings.csv` / `scores.csv`, the lab before/after captures (`tests/fixtures/lab/`, #34), and gitleaks installed (`brew install gitleaks` / `apt install gitleaks`).
- **Close everything that isn't the hotspot:** cable, venue Wi-Fi, VPN.

## 1. Re-run one Test Set file: it must match the upload

The jury picks a file. Re-run it alone and compare with the upload. **If this differs, Test Set accuracy (30%) scores 0.**

```bash
mkdir -p /tmp/one && cp <TestSet>/<FILE>.xml /tmp/one/
bilet analyze /tmp/one --out /tmp/rerun --lang en
grep '^<FILE>.xml,' <upload>/findings.csv | cmp - <(grep '^<FILE>.xml,' /tmp/rerun/findings.csv) && echo SAME
grep '^<FILE>.xml,' <upload>/scores.csv /tmp/rerun/scores.csv
```

Real run (V4 from the Validation Set): `1 files, 6 findings, 0 unreadable`, the rows are identical, and the score is `V4_legacy.xml,25` in both.

**If it differs:** you're not on the `final` build (`git describe --tags`), or the upload came from another machine. Say so honestly; don't edit files.

## 2. Hands-on: "Which device is the most dangerous, and what should I do first?"

A jury member uses the UI without help. Open the scan they'll ask about, e.g. a Test Set file through **"Open a scan file"** on the home screen, or `bilet serve --result <file>.json` (`bilet analyze <folder> --json` writes those).

For the V2 example, the score is **40**, the camera at **192.168.1.40** has the highest risk total (**30 points**), and the first action explains how to address its exposed camera stream. Read the current device-specific instruction on screen; wording may change as fixes improve. The **Check again** control follows the score and first action.

The jury should be able to identify the priority device and the fixing action from the page itself. Port numbers are explained on the page, and catalog codes are visible on the finding cards and `/risks` for matching the requested finding.

The language switch (Română / English) is at the top. Hands off: let them find it.

## 3. Explanations and fixes for three findings the jury names

Open **`/risks`** (linked from every page). All 15 catalog codes are there, each with its plain RO/EN explanation, 1–5 fix steps and CIS/OWASP references, so a code that isn't in the scan on screen works too. Each finding on the home screen links to its entry (`/risks#CAMERA_STREAM_EXPOSED`).

## 4. Guardrail: try a public IP and the venue network; it must refuse

```bash
bilet scan 8.8.8.8 --confirm --lang en
bilet scan <venue range, e.g. 192.168.1.0/24> --confirm --lang en
```

**Use the real venue range, not the example.** Find it before the session: join the venue Wi-Fi briefly on any laptop and run `ip route` (Linux) or `netstat -rn` (macOS), or ask the organizers. Then switch back to `RSH-dork_unit` only. The refusal then names the exact network the jury asked about.

Real run:

```
The address 8.8.8.8 is on the internet, not in your home network. The bilet app only checks your own network.
(PUBLIC_ADDRESS)                                                             exit=3
The address 192.168.1.0/24 is not part of the network this computer is connected to. The bilet app only checks the network this computer is connected to.
(OUTSIDE_ALLOWLIST)                                                          exit=3
```

Also good to show:
- `bilet scan` with no `--confirm` explains what it *would* scan (`CONFIRM_REQUIRED`).
- `100.64.0.1` (the mobile operator's range), `127.0.0.1`, `router.lan` and `10.0.0.0/16` are all refused, each with its own reason.

## 5. Open an unreadable file: a clear error, no crash

```bash
mkdir -p /tmp/broken && cp tests/fixtures/validation/V7_broken.xml /tmp/broken/
bilet analyze /tmp/broken --out /tmp/bo --lang en ; cat /tmp/bo/scores.csv
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

The lab captures (#34) are the real ones. Load **only L1 and L2** into a **fresh** history, then
open **`/history`**. Not the whole folder: L3 (score 20, the other toggles) is newer than L2
(55), the trend runs from the first scan to the last and the compare view defaults to the two
newest, so with L3 loaded `/history` would say the score went *down* (#225). Older scans in
your normal history would muddle the chart too.

```bash
export TOOL_DATA_DIR=$(mktemp -d)        # a fresh history for this check only
pair=$(mktemp -d)
cp tests/fixtures/lab/L1_default.xml tests/fixtures/lab/L2_after_fix.xml "$pair"/
bilet analyze "$pair" --out /tmp/lab --save --lang en
bilet serve                              # same shell, so it uses the same TOOL_DATA_DIR
```

Expected: `saved 2 scans to the local history`, and `/history` says the score went up from
25 to 55. Afterwards, `unset TOOL_DATA_DIR` (or open a new terminal) to get your normal history
back; the temporary one can simply be deleted.

Real run on `main` `c7d2b03`, 8 Nov (the L1 + L2 captures from #227, with a fresh `TOOL_DATA_DIR`):
- The command prints `2 files, 16 findings, 0 unreadable` and `saved 2 scans to the local history`. `scores.csv` gives L1 25 and L2 55.
- `/history` shows **"Your score went up from 25 to 55"**, the trend chart, and the compare view with **"Problems you fixed (2)"**: the settings page without encryption (camera, `80/tcp`) and Telnet (camera, `2323/tcp`), plus "Ports that are now closed (2)".

**Live version, if time allows (MASTERPLAN §4.3):**
1. `bilet scan --confirm`.
2. Turn Telnet off on the camera, in one of three ways:
   - the camera's own settings page (#144): `http://<camera-ip>/`, user `admin`, the device ID on its label, "Telnet / remote access" → Turn off. This is the way that follows our fix steps, so use it when the jury has just read them;
   - the lab manager on the Pi 5 (#155): `ssh -L 8090:127.0.0.1:8090 <user>@<pi5>`, open `http://127.0.0.1:8090/`, telnet → Turn off;
   - `ssh <user>@<camera-pi> sudo labctl fix telnet` from the laptop.

   Its LED turns green once nothing weak is left on it.
3. `bilet scan --confirm` again.
4. The home screen and `/history` show the score climbing.

## 7. No secrets in the repository

```bash
gitleaks version                                 # check before the session
gitleaks git . --redact --verbose                # gitleaks 8.19 or newer
gitleaks detect --source . --redact --verbose    # older versions (newer ones accept it with a deprecation warning)
```

Use the command that matches the laptop's version, so a deprecation warning doesn't look like a failure live. A pass ends with `no leaks found`. CI runs the same scan on every push and PR (the `gitleaks (NFR-01)` check), so the PR page is a backup if gitleaks isn't installed. The API key is only ever in the environment (`.env` is git-ignored; `.env.example` holds empty placeholders).

## Extra: masked MACs, if the jury asks

"Masked MACs" is a yes/no item in the security score (MASTERPLAN §3.5), but none of the seven checks shows it. Have this ready, for example right after check 7. Use a file whose input really has full MACs:

```bash
grep -cE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' tests/fixtures/validation/V2_smart_home.xml   # the input: 4 full MACs
bilet analyze tests/fixtures/validation --out /tmp/macs --json --lang en                   # no --save: the history stays as it is
grep -ho '"mac[a-z_]*": *"[^"]*"' /tmp/macs/json/V2_smart_home.json                     # only "mac_masked"
grep -rEo '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' /tmp/macs                                # pass: prints nothing
```

Real run on `main` `c31c035`, 8 Nov:
- The input has 4 full MACs.
- The JSON has only `"mac_masked": "50:C7:BF:xx:xx:xx"`, `"C0:56:E3:xx:xx:xx"`, `"B8:27:EB:xx:xx:xx"` and `"F4:F5:D8:xx:xx:xx"`. That's the maker's half, never the device's own.
- The last grep finds no full MAC in any JSON file or in `findings.csv` / `scores.csv`. The CSVs have no MAC column at all.

**On screen:** each device card on the home screen shows the same masked form next to the hostname. The history tells devices apart by a salted HMAC of the MAC (`device_key`), never the MAC itself. A fresh history saved from the Validation Set has no full MAC in `history.sqlite3`.

**What stays raw, and where:** the nmap XML that `bilet scan --confirm` saves in `scans/` is the raw scan, with full MACs. It stays on this laptop, the folder is `0700`, and `scans/` is git-ignored. The lab captures in the repo went through `lab/sanitize` (Test Set runbook step 1b checks this).

## Still to do on the day (needs a human on the hotspot)

- Run all seven once on the scanner laptop at the `final` tag, and time the session.
- Check 6 with the real lab captures from #34 (score 25 → 55 for L1 → L2).
- `bilet scan --confirm` on the full hotspot: record how long it takes (NFR-07: a /24 in under 5 minutes) and check that the laptop's own IP doesn't appear as UNKNOWN_DEVICE.
