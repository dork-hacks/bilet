# Master Plan: R Systems Hackathon 2026

> **Read this first.** This file briefs teammates (and their Claude Code sessions) on the main idea, the hard rules and who owns what.
> The full brief is in `R Systems Hackathon 2026 - Participant Brief.pdf`. When this file and the brief disagree, **the brief wins**.
> **The project name is not decided yet.** Call it "the tool" in code and docs until it is, and keep the name in a single config value so changing it later is trivial.

---

## 1. The challenge in one paragraph

In 24 hours we build a tool that scans a small network we own (a phone hotspot), finds devices and open ports, classifies them using the **official finding catalog**, gives a **standard score**, explains each risk in plain **Romanian and English**, gives step-by-step fixes and keeps a **history** that shows the score improving after fixes. Users are parents and grandparents, not security experts. Jury tagline: *"not a wrapper around nmap."*

## 2. How we are scored, and what that means for priorities

| Weight | Criterion | Implication |
|---|---|---|
| **30%** | Test Set accuracy | Deterministic rules engine that matches the catalog exactly. Extra findings cost as much as correct ones earn. If the live re-run differs from the upload, this criterion is **0**. |
| **20%** | Ease of use | A jury member must answer *"Which device is the most dangerous, and what do I do first?"* without help. The home screen answers exactly that. |
| 15% | Explanation quality | Hand-checked RO/EN text for every catalog code. |
| 15% | Pitch and teamwork | Juniors and seniors both speak. |
| 10% | Security and responsibility | Guardrail, broken file, masked MACs, no secrets (gitleaks), before/after. |
| 10% | Innovation | The Raspberry Pis and the AI layer (sections 4 and 5). |

**Priority order: rules engine and CSV export → guardrail and live scan → UI → history → AI → hardware polish.**
Hardware and AI work must never block the engine.

## 3. Non-negotiable rules (break one and we lose points or get disqualified)

1. **Scan only our own hotspot subnet.** Never the venue Wi-Fi, other teams or public IPs. Unauthorized access is a crime in Romania (Criminal Code Art. 360).
2. **Simulate, do not expose.** Weak services are fake banners or empty daemons. No real shells, data or passwords behind them.
3. **No LLM in findings, severities or scores.** Those come only from our rules and are identical on every run. The LLM may only write explanations, fixes and Q&A text, and it must fall back to built-in text when it is unavailable.
4. **No secrets in the repo.** API keys come from environment variables. Keep a `.env.example`, keep `.env` in `.gitignore`, and run gitleaks before every push.
5. **Mask MACs everywhere** (`B8:27:EB:xx:xx:xx`). Hostnames and history stay local. Provide a one-click "delete my history".
6. **Treat all input as hostile.** Parse XML with `defusedxml` (no XXE), enforce size limits, and escape banners in the UI. Banners are also a prompt-injection vector (see 5.4).
7. **Least privilege.** Only the live scan step runs as root (calling nmap). The analyser and UI run unprivileged.
8. **Build the CLI first and the UI second.** A polished UI without working functionality scores nothing.

## 4. Our unique angle: 3 × Raspberry Pi 4 + 1 × Raspberry Pi 5

### 4.1 "House in a box": the 3 Pi 4s are the target devices

Each Pi 4 plays a typical household device. This is our hotspot lab (minimum lab required by hour 3).

**The hotspot is `RSH-dork_unit`:** one team phone, WPA2 or WPA3, a strong password and a mobile data limit. The brief says `RSH-<team-number>`; we use our team name `dork_unit` instead (decided by Mef05, #41). Every Pi and the scanner laptop join this network and nothing else.

| Box | Plays the role of | Services (fake or empty) | Catalog codes |
|---|---|---|---|
| Pi 4 #1 | IP camera | RTSP on 554, HTTP page titled "Camera Login", BusyBox telnet banner on port 2323 | CAMERA_STREAM_EXPOSED, HTTP_ADMIN_CLEARTEXT, TELNET_OPEN |
| Pi 4 #2 | Old office server | FTP banner `220 (vsFTPd 2.3.4)`, fake Redis replying `-NOAUTH`, Samba with no shares, SSH (key-only) | FTP_CLEARTEXT, OUTDATED_SERVICE, DB_EXPOSED, SMB_EXPOSED, SSH_OPEN |
| Pi 4 #3 | "Mystery" smart hub | Mosquitto 1.6 (no data), SSDP responder on UDP 1900, locked-down snmpd, fake JetDirect on 9100, **random MAC and no hostname** | MQTT_EXPOSED, UPNP_EXPOSED, SNMP_EXPOSED, PRINTER_RAW_EXPOSED, UNKNOWN_DEVICE |

- **Status LEDs:** the on-board LEDs (`/sys/class/leds`) show device state. Blinking red means it has a weak service, steady green means it's fixed. No extra hardware is needed. If we have buttons, a GPIO "fix" button per Pi turns its weak service off.
- **Tune the default lab so the score starts at about 25, not 0.** The score floors at 0, so a lab worth −50 would hide the first fixes. Enable the other services as toggles for extra captures and test fixtures.
  - Default set: telnet (20) + HTTP admin (10) + FTP (10) + outdated vsftpd (20) + MQTT (10) + unknown device (5) + SSH (0). That is 75 points, so the score is 25, with 7 finding types.
- **Fake services must fool `nmap -sV`.** Verify that each one is labelled with the catalog's service name. Telnet needs IAC negotiation bytes, SNMP needs a valid response packet and UPnP needs an HTTP 200 reply with a `SERVER:` header to M-SEARCH.
- Fake service scripts and setup live in `lab/` with one setup script per role.

### 4.2 The Pi 5 is the always-on home guardian (the product vision)

- It runs **the same code** as the laptop: the UI, scheduled rescans, change alerts (FR-13: new device or newly opened port) and passive mDNS/SSDP listening (allowed by the rules).
- It can optionally run a **local LLM** (Ollama with a small model) as the offline/private AI provider (see 5.5).
- The brief says the scanner is a **laptop**. Official live checks and the Test Set run happen on the laptop. The Pi 5 is pitched as "the same tool in a home-appliance form factor". Ask a mentor before making it the official scanner.

### 4.3 Demo moment

The jury sees a red score. We press "fix" on the camera Pi, its LED turns green, the guardian re-checks and the score climbs. Then we power on Pi #3 and the UI shows "A new device joined your network". This one sequence covers the history live check, FR-13 and innovation.

## 5. The AI layer: an LLM API that makes results easy to understand

We integrate an LLM through an API to turn raw findings into friendly, personal language. **The LLM never decides what is wrong. It only explains what the rules already found.**

### 5.1 Where the AI adds value

1. **Personalised explanations:** turns the template explanation into one about *this* device ("Your camera can be watched by anyone on your Wi-Fi…"), at most 2 sentences, in RO and EN.
2. **"What should I do first?" summary:** a short plan for the whole network, in the order the rules already ranked the findings.
3. **Grounded Q&A chat (FR-12):** for example, *"Is it safe that my printer has port 9100 open?"* The answer uses only scan evidence and says **"the scan can't tell me that"** when the evidence doesn't cover it.
4. **Simpler fix wording and follow-ups:** for example, *"I don't know how to open my router settings."* It rephrases our template steps. It must not invent menu paths for specific router models.

### 5.2 Architecture

```
rules engine ──► findings (deterministic, no AI)
                     │
                     ▼
          evidence builder ── anonymises (Device A/B, no MAC, no hostname)
                     │
                     ▼
            LLM provider interface ── cloud API | local Ollama on Pi 5 | none
                     │
                     ▼
          grounding checker ── rejects anything not in the evidence
                     │
           pass ─────┴───── fail / timeout / no key
             ▼                    ▼
        AI text shown       built-in template text shown
```

- **A pluggable provider** chosen by env var (`LLM_PROVIDER`, `LLM_API_KEY`, `LLM_MODEL`). The default is a cloud API (for example Claude via the Anthropic API, using a fast, cheap model). Alternatives are a local Ollama model on the Pi 5, or `none`.
- **Built-in templates are always the baseline.** Every catalog code has hand-written RO/EN explanations and 1–5 fix steps. The app is fully usable with AI turned off, and the AI only improves on these texts.
- **Timeout of about 5 s**, then fall back to the templates. The UI shows a small label: "Explained by AI" or "Standard explanation".
- **Cache** AI outputs by a hash of the evidence, so the demo is fast and repeatable. Pre-generate them for our lab scans.

### 5.3 The grounding checker (governance, NFR-06)

This is a strong jury talking point, because R Systems stresses *governed* AI.
- The LLM receives structured evidence with IDs and must return JSON where every sentence cites an evidence ID.
- The checker extracts every IP, port, number, CVE pattern, URL and phone number from the output. **If any of them isn't in the evidence, the answer is rejected and the template is used instead.**
- It also enforces at most 2 sentences per explanation, both languages present, and no unexplained jargon (a small banned-terms list).
- Log rejections locally and show the count in the pitch ("the AI tried to invent something N times; we blocked it").

### 5.4 Privacy and security of the AI layer

- **Send the minimum:** catalog codes, ports, service product and version, and the device-type guess. **Never send MACs or hostnames.** Replace devices with pseudonyms ("Device A") and map them back locally.
- **Never send raw banners or page titles.** They are attacker-controlled and could carry prompt injection ("ignore previous instructions…"). If a field is needed, sanitise it, truncate it and mark it as untrusted data.
- AI is **opt-in** with a visible toggle, and the UI says what data leaves the device.
- The API key lives only in the environment. Never commit it, log it or send it to the frontend. All calls go through our backend.

### 5.5 Optional: local LLM on the Pi 5

This is the privacy pitch: *"your network map never leaves your house."* Small models are weaker in Romanian, so the hand-written templates stay authoritative. The local model mainly handles Q&A. Pre-download the model at home, not over the hotspot.

## 6. Technical architecture

**Stack:** Python 3.12, `defusedxml`, SQLite, FastAPI, and Jinja + HTMX for the UI (no build step, runs on the Pi's ARM). One repo.

```
<tool> scan --confirm            # live scan (needs sudo, only this step calls nmap)
<tool> analyze <folder>          # offline, writes findings.csv + scores.csv
<tool> serve                     # web UI (unprivileged)
```

### 6.1 Rules engine details (the 30%)

- Only count ports whose state is exactly `open`. Not `open|filtered`, not `filtered`. Skip hosts that aren't up.
- Match on nmap's service `name`, **not the port number**. Check the validation set for how `method="table"` entries should be treated.
- **HTTP_ADMIN_CLEARTEXT:** `name == "http"`, no `tunnel="ssl"`, and the `http-title` script output contains login / admin / config / setup / router / settings (case-insensitive).
- **SMB_EXPOSED:** one per device, on port 445 if it's open, otherwise 139.
- **UNKNOWN_DEVICE:** no MAC vendor, no hostname and at least one open port. **The port column is empty.**
- **UPNP / SNMP:** only on UDP.
- **OUTDATED_SERVICE** is an **extra** row alongside the service's own finding. The outdated list is vsftpd 2.3.4, OpenSSH below 7.4 (`7.2p2` counts), Apache httpd 2.2.x or older, IIS 7.5 or older, and Samba 3.x or older.
  - ⚠️ Nmap often reports `Samba smbd 3.X - 4.X`, which is ambiguous. **Ask a mentor at hour 0.** Until they answer, flag it only if the upper bound is 3 or lower.
- **Score** = max(0, 100 − sum of finding points).
- **Unreadable file** (truncated, empty, not an nmap file, XXE, too large) → `ERROR` in `scores.csv`. Never crash, and continue with the other files.
- **Determinism:** sort rows (file, ip, port, code) so output is byte-identical between runs.
- **Golden test:** `make validate` diffs our output against the Validation Set's 24 expected rows and 7 scores. Run it on every commit.
- From hour 16, write **our own trap files**: ssl/http, filtered ports, IPv6, several hostnames, `method="table"`, an XXE payload, a 0-byte file, a huge file.

### 6.2 Guardrail (FR-02, demonstrated live)

- The allowlist defaults to the connected subnet (detected automatically, FR-01).
- Refuse anything that isn't private, and **also refuse 100.64.0.0/10** (the mobile operator's CGNAT range, which Python's `is_private` doesn't cover).
- Refuse hostnames and ranges larger than a /24.
- Live scans need `--confirm`.

### 6.3 Live scan

- Discover live hosts first (ARP or ping), then port-scan only those: top 1,000 TCP ports plus UDP 53, 123, 161, 1900 and 5353, with `-sV --script http-title --max-rate 100`.
- A full /24 sweep at 100 pps would take about 42 minutes. Scanning only live hosts keeps a scan under 5 minutes (NFR-07).
- Save every scan as nmap XML in the same format as the standard data.

### 6.4 History (FR-10)

- Store every scan in local SQLite.
- Order scans by the nmap `start` timestamp and add a picker to compare any two. All validation files use 192.168.1.0/24, so the subnet can't tell you which scans belong together.
- The diff shows new and removed devices, opened and closed ports, resolved findings and the score trend.
- Identify devices by a **salted HMAC of the MAC** (the salt is local), never the raw MAC.

### 6.5 UI essentials

- **The home screen** shows a big traffic-light score (icon + label + number), then *"Most dangerous device: X. Do this first: Y."*
- Then devices, findings with fixes, and history with a before/after chart. Include a RO/EN switch and a "delete my history" button.
- **Accessibility:** text at least 16 px, colour is never the only signal, keyboard navigable, WCAG AA contrast.
- **Bonus signals:** map each catalog code to CIS Controls / OWASP IoT Top 10, and test the Romanian text with a real non-technical person.

## 7. Team split (adjust to our actual team)

| Owner | Part | Milestone |
|---|---|---|
| Senior A | Parser, rules, scoring, CSV export, golden tests | 24/24 validation rows by hour 10 |
| Senior B | Network detection, live scan, guardrail, history/diff, Pi 5 service | Out-of-scope scan refused by hour 14 |
| Junior C | Pi 4 lab, fake services, LEDs, scan captures | 3 scans saved by hour 3 |
| Junior D | UI, accessibility, RO/EN | Score, findings and history visible by hour 16 |
| Pair | RO/EN templates for all 15 codes, CIS/OWASP mapping, AI layer + grounding checker, pitch | Templates by hour 12, AI by hour 16 |

## 8. Timeline

| Hour | Goal |
|---|---|
| Before the event | Flash Pi OS Lite 64-bit and set up SSH keys. **Download all packages, images and models on home Wi-Fi** (hotspot data is limited and the scanner can't use venue Wi-Fi at the same time). Test the phone hotspot with 5 or more clients (iPhone limits clients; some Androids isolate them). Check whether pre-written code is allowed. |
| 0–1 | Read the validation set, ask the open questions (section 9), set up the repo skeleton, agree on the `Finding` data model. |
| 1–3 | Lab running on the hotspot with 3 scans saved. Parser reads V1–V7. |
| 3–10 | Rules engine reaches 24/24. Template texts. UI skeleton. Guardrail. |
| 10–16 | Live scan, history/diff, Pi 5 guardian, AI layer and grounding checker. **Mentor check at hour 16.** |
| 16–20 | Trap files, non-technical Romanian test, gitleaks, pitch rehearsal of all 7 live checks. |
| 20–21 | Run on the Test Set, sanity-check the new traps against the rules, upload, **tag `final` right away**. No code changes after the upload. |
| 21–24 | Jury: 7-minute pitch plus 8 minutes of live checks. |

**The 7 live checks, in order:** re-run one Test Set file · jury hands-on task · explanations for 3 named findings · guardrail refuses a public IP and the venue network · broken file shows an error without crashing · before/after from our own lab · gitleaks clean.

## 9. Open questions

- [ ] **Project name** (undecided)
- [ ] Team size and seniority, so the split in section 7 can be adjusted
- [ ] Scanner laptop OS (on macOS: install nmap with brew; the live scan needs sudo)
- [ ] Pi 5 RAM (the local LLM needs 8 GB)
- [ ] Which LLM API and who holds the key (never in the repo)
- [ ] Do we have LEDs, buttons or a small screen for the Pis?
- [ ] Which phone acts as the hotspot (client limit, client isolation)?
- [ ] For mentors: Samba `3.X - 4.X` handling, `method="table"` handling, whether the Pi 5 can be the official scanner

## 10. Main risks

| Risk | Mitigation |
|---|---|
| Live re-run differs from the upload | Run the Test Set and the re-run on the same laptop with pinned dependencies |
| Hotspot isolation or client limit | Fallback setup D (single-laptop Docker), plus lab XML captures kept in the repo |
| LLM slow, down or hallucinating | 5 s timeout, grounding checker, template fallback, cache |
| Hardware eats engine time | Only Junior C works on hardware before the engine passes 24/24 |
| Fake banners not recognised by nmap | Verify each one with `nmap -sV` during prep |
