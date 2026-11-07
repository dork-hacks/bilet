# bilet: technical summary

bilet scans a network you own, scores it against the official catalog and explains each risk in plain Romanian and English, with fixes and a history.

## Lab setup

- **Hotspot:** a Raspberry Pi 5 on OpenWrt serves `RSH-dork_unit` (WPA2/WPA3), locked down to key-only SSH.
- **Targets:** three Pi 4s play a camera, an old office server and a "mystery" smart hub. Their weak services are **simulated** (`lab/`): no login on them ever works.
- **Default lab:** score 25 with 7 finding types. `labctl fix telnet` and `labctl fix http` raise it to 55.
- **Scanner:** a laptop on the hotspot and nothing else.

## Architecture

`bilet scan --confirm` runs all five steps, `bilet analyze <folder>` runs steps 3–5 on saved files, and `bilet serve` shows the results.

1. **Guardrail:** private ranges of /24 or smaller in the connected subnet only. Public, CGNAT 100.64.0.0/10, hostnames and a missing `--confirm` are refused.
2. **Live scan:** `nmap -sn`, then only the live hosts. Top 1,000 TCP ports plus 5 catalog ports, 5 UDP ports, `-sV`, http-title, 100 packets/s. **Only these two nmap runs use sudo.**
3. **Parser:** `defusedxml` with a 20 MiB limit. A broken file becomes `ERROR`, never a crash.
4. **Rules:** the 15 catalog codes are data, matched on nmap's service name and only on `open` ports. Deterministic, with no AI.
5. **Score:** max(0, 100 − points), then CSV export, SQLite history and the FastAPI + Jinja UI.

MACs are masked and devices keyed by a salted HMAC. History stays local, with one-click delete.

**Checked on `main` (`c9769b6`), 7 Nov:**

- 803 tests pass.
- `make validate` reproduces the Validation Set's 24 findings and 8 scores byte for byte (V7 is `ERROR`), plus our 25 trap files and a generated 21 MiB one (`ERROR`).
- CI runs gitleaks, the tests, the lint check and the golden test on every PR.

## Assumptions

These are defaults the mentors haven't ruled on yet (#8):

- **Samba:** nmap's "3.X - 4.X" is judged by its upper bound, so it isn't outdated.
- **`method="table"`:** port-table names count, or no real printer (9100) or UPnP device (UDP 1900) could ever be found.
- **HTTP_ADMIN_CLEARTEXT:** only the service name exactly `http` counts. A redirect message isn't a title, and title words match as case-insensitive substrings.
- **FTP and telnet over SSL** still count as cleartext. **OUTDATED_SERVICE** appears even without the port's own finding, and old Samba gives one per device.
- **History pairing:** by device key, then IP plus MAC vendor, then hostname plus MAC vendor, because V6a → V6b changes every MAC.

## Limitations

- **Coverage:**
  - IPv4 only for live scans.
  - Results depend on what the installed nmap's `-sV` reports.
  - Silent UDP services (`open|filtered`) aren't counted.
  - Ports outside the scanned list are missed.
- **Outdated list:** the catalog's fixed list, not a CVE feed.
- **The scanner itself:** the laptop doesn't scan its own address.
- **History:** a device that changes its MAC, IP and hostname at once shows as removed plus new.

## LLM use

- **What it does:** Claude Haiku (Anthropic API, opt-in, through our backend) only rewords explanations, writes the "do this first" summary and answers questions. Findings, severities and scores never touch it.
- **What it sees:** catalog codes, ports, services and sanitised versions under pseudonyms. Never IPs, MACs, hostnames, banners or page titles.
- **Grounding checker:** one IP, number, CVE or URL that isn't in the evidence rejects the whole reply. So do more than 2 sentences, a missing language or banned jargon.
- **Fallback:** a rejection, an error or a 5 s timeout shows the hand-written text. Replies are cached by evidence hash.
- **How we built it:** Claude Code agents, coordinated through GitHub issues. Every PR is reviewed by another agent, and sudo, lab and plan changes also by a human.
