# bilet

A local network security checker for the R Systems Hackathon 2026. It scans a small network you own, explains each risk in plain Romanian and English, gives step-by-step fixes and a score, and keeps a history so you can see the score improve.

The name comes from "bile, bile", Romanian Gen-Z slang for "good": that's what it makes your network. The command is `bilet`; `tool` still works and does exactly the same thing. Team plan: [MASTERPLAN.md](MASTERPLAN.md). How we work: [WORKFLOW.md](WORKFLOW.md).

## Setup

Needs Python 3.12 and `make`. For live scans, also nmap and admin rights.

```bash
make setup
```

This creates `.venv/` and installs the pinned dependencies. Then either activate it (`source .venv/bin/activate`) or call `.venv/bin/tool` directly. For the AI layer, copy `.env.example` to `.env` and fill it in. The tool works without it.

## Analyse scan files (offline)

```bash
tool analyze path/to/folder --out out/
```

Writes `out/findings.csv` and `out/scores.csv` for every nmap XML file in the folder, in the organizers' exact format (on the Validation Set the output is byte-identical to their answer key). Unreadable files get `ERROR`, are named on the screen, and the run continues. Add `--json` for one full result per file in `out/json/`. All commands and help use Romanian by default. Select English with `--lang en` before or after the subcommand: `bilet --lang en --help`, `bilet analyze --lang en --help`, or `bilet --lang en detect`. If repeated, the last `--lang` value wins. Flags, paths, catalog/error codes and CSV/JSON output stay the same in both languages.

## Live scan (your own network only)

```bash
tool detect
```

```bash
tool scan --confirm
```

`detect` shows the network you're connected to. `scan` only scans that subnet, refuses public and out-of-scope ranges, and needs `--confirm`. Only its nmap step runs with admin rights (it asks for your password); the analysis and the UI never do. Run `tool scan` without `--confirm` to see what it would scan. Extra ranges (for example a second lab network) can only be added explicitly with `TOOL_SCAN_ALLOWLIST=192.168.50.0/24`, and they must be home ranges of at most 256 addresses.

The scan first finds the devices that are up, then checks only those: the top 1,000 TCP ports from your nmap's own `nmap-services` list, plus the catalog ports outside it (1883, 6379, 6380, 8883, 27017), plus UDP 53, 123, 161, 1900 and 5353, at most 100 packets a second. The XML is saved under `data/scans/` by default (`TOOL_DATA_DIR/scans` when configured, readable only by you), analysed and added to the local history, so `tool serve` shows it. The computer running the scan isn't checked itself: a scan of your own address goes past your own firewall, so it wouldn't show what the rest of the network sees. If nmap's data file isn't found, set `TOOL_NMAP_SERVICES` to the path of `nmap-services`. Start `tool scan` as a normal user, not with sudo.

## Web interface

```bash
bilet serve
```

Then open <http://127.0.0.1:8000>. By default it listens on this computer only. `--port` changes the port. Don't use `--host 0.0.0.0` or your network address: the interface has no password, so anyone on the same Wi-Fi could see your results and delete your history. It refuses to start as root: only the live scan's nmap step ever needs admin rights. The app accepts only loopback Host names/addresses (localhost, 127.0.0.1 or ::1) and refuses framing. Network-address URLs and custom DNS names are rejected. Every page has a Română / English switch.

- **Home (`/`):** the score as a traffic light (icon, label and number), the most dangerous device and the first thing to do, then every device with its problems and fix steps, and an alert when a new device or a new open port appears. It shows the newest scan in the history; `--result path/to/result.json` (from `bilet analyze --json`) shows that file instead. "Open a scan file" checks any nmap XML file without saving it, and a broken file gives a plain error, not a crash.
- **Every risk explained (`/risks`):** the explanation and fix steps for all 15 problem types, with their CIS Controls and OWASP IoT references.
- **History (`/history`):** the score over time, a comparison of any two scans (new and removed devices, opened and closed ports, fixed problems), and "Delete my history".

History, the device-key salt, the AI cache and default raw scan XML live in `data/` (git-ignored; set `TOOL_DATA_DIR` to move it). "Delete my history" removes these managed files, including `data/scans/`. XML contains full device identifiers, so remove unwanted copies too. Explicit `--scans-dir` locations outside this managed folder and captures created by older versions in the separate `scans/` folder are **not** deleted or moved automatically; remove those yourself. A deletion failure is reported instead of claiming everything was removed.

### AI explanations (optional)

AI is off unless you set it up and then turn it on with the button on the home screen. When it's on, an AI service rewrites the explanations for your devices, suggests what to do first, and answers questions about your scan. It never decides what is wrong or what the score is: those come only from the built-in rules. It is sent only the problem types, port numbers, program names and versions, and the device type, never MAC addresses, IP addresses, device names or what the devices say about themselves. If it is slow, unavailable, or says something the scan doesn't support, the built-in text is shown instead, labelled "Standard explanation".

`bilet` reads its settings from the environment; it doesn't read `.env` by itself. So copy `.env.example` to `.env`, fill in `LLM_PROVIDER=anthropic` and `LLM_API_KEY`, and load it into the shell before starting the server:

```bash
set -a; . ./.env; set +a
bilet serve
```

Never commit `.env`: it is git-ignored, and CI runs gitleaks on every push.

## Development

```bash
make test
```

```bash
make lint
```

```bash
make validate
```

`make validate` is the golden test: it runs the CSV export on the organizers' Validation Set and checks both files are byte-identical to their answer key, and that two runs give the same bytes. Once our own trap files land (#23), it checks those too.

CI runs gitleaks, the tests, the lint check and `make validate` on every PR.
