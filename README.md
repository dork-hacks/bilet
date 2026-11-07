# bilet

A local network security checker for the R Systems Hackathon 2026. It scans a small network you own, explains each risk in plain Romanian and English, gives step-by-step fixes and a score, and keeps a history so you can see the score improve.

The product name isn't decided yet, so the docs call it "the tool" and the command is `tool`. Team plan: [MASTERPLAN.md](MASTERPLAN.md). How we work: [WORKFLOW.md](WORKFLOW.md).

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

Writes `out/findings.csv` and `out/scores.csv` for every nmap XML file in the folder, in the organizers' exact format (on the Validation Set the output is byte-identical to their answer key). Unreadable files get `ERROR`, are named on the screen, and the run continues. Add `--json` for one full result per file in `out/json/`, and `--lang en` for English messages (Romanian is the default).

## Live scan (your own network only)

```bash
tool detect
```

```bash
tool scan --confirm
```

`detect` shows the network you're connected to. `scan` only scans that subnet, refuses public and out-of-scope ranges, and needs `--confirm`. Only its nmap step runs with admin rights (it asks for your password); the analysis and the UI never do. *(Coming in #18, #19 and #20.)*

## Web interface

```bash
tool serve
```

*(Coming from the UI issues.)*

## Development

```bash
make test
```

```bash
make lint
```

CI runs gitleaks, the tests and the lint check on every PR.
