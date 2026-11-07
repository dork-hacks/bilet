"""Command-line entry point. Each subcommand is filled in by its own issue."""

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from tool import __version__
from tool.config import DISPLAY_NAME

# subcommand -> (help text, issue that implements it)
COMMANDS = {
    "analyze": ("analyse a folder of nmap XML files and write findings.csv / scores.csv", 16),
    "detect": ("show the network this computer is connected to", 19),
    "scan": ("scan your own network (needs --confirm and admin rights)", 20),
    "serve": ("start the web interface", 29),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tool", description=f"{DISPLAY_NAME}: a home network security checker"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    for name, (help_text, _issue) in COMMANDS.items():
        cmd = sub.add_parser(name, help=help_text)
        if name == "serve":
            cmd.add_argument(
                "--result", type=Path, help="show this ScanResult JSON (until history lands)"
            )
            cmd.add_argument("--host", default="127.0.0.1", help="default: this computer only")
            cmd.add_argument("--port", type=int, default=8000)
        if name == "scan":
            cmd.add_argument(
                "targets", nargs="*", help="addresses or ranges (default: the connected subnet)"
            )
            cmd.add_argument(
                "--confirm", action="store_true", help="confirm this is your own network"
            )
            cmd.add_argument("--lang", choices=("ro", "en"), default="ro")
            cmd.add_argument(
                "--scans-dir",
                type=Path,
                default=Path("scans"),
                help="where to save the nmap XML (default: scans/, git-ignored)",
            )
        if name == "analyze":
            cmd.add_argument("folder", type=Path, help="folder with nmap XML files")
            cmd.add_argument(
                "--out", type=Path, default=Path("out"), help="where to write the CSVs"
            )
            cmd.add_argument(
                "--json", action="store_true", help="also write one ScanResult JSON per file"
            )
            cmd.add_argument(
                "--save", action="store_true", help="also store the scans in the local history"
            )
            cmd.add_argument("--lang", choices=("ro", "en"), default="ro")
        if name == "detect":
            cmd.add_argument("--lang", choices=("ro", "en"), default="ro")
            cmd.add_argument("--json", action="store_true", help="machine-readable output")
    return parser


_DETECT_LABELS = {
    "ro": ("Interfață", "Adresa acestui calculator", "Rețea", "Router (gateway)"),
    "en": ("Interface", "This computer's address", "Network", "Router (gateway)"),
}


# Until area:content adopts the scan texts into tool.content. {targets}, {path}, {score}
# and {findings} are filled in as plain text.
_SCAN_TEXT = {
    "RUN_AS_ROOT": {
        "ro": "Nu porniți scanarea ca administrator (root). Porniți-o ca utilizator obișnuit:"
        " programul cere parola doar pentru nmap.",
        "en": "Don't start the scan as administrator (root). Start it as a normal user:"
        " the tool asks for the password for nmap only.",
    },
    "START": {
        "ro": "Se verifică {targets}. nmap are nevoie de drepturi de administrator,"
        " așa că este posibil să vi se ceară parola.",
        "en": "Checking {targets}. nmap needs admin rights, so you may be asked for your password.",
    },
    "SELF_SKIPPED": {
        "ro": "Acest calculator ({address}) nu este verificat: o scanare a lui însuși"
        " nu vede ce vede restul rețelei.",
        "en": "This computer ({address}) isn't checked: a scan of itself doesn't see"
        " what the rest of the network sees.",
    },
    "DONE": {
        "ro": "Scanare salvată: {path}. Scor: {score}/100, {findings} probleme găsite."
        " Vedeți rezultatele cu: tool serve",
        "en": "Scan saved: {path}. Score: {score}/100, {findings} findings."
        " See the results with: tool serve",
    },
    "NMAP_NOT_FOUND": {
        "ro": "nmap nu este instalat. Instalați-l (de exemplu sudo apt install nmap"
        " sau brew install nmap) și încercați din nou.",
        "en": "nmap isn't installed. Install it (for example sudo apt install nmap"
        " or brew install nmap) and try again.",
    },
    "NMAP_DATA_NOT_FOUND": {
        "ro": "Nu găsesc lista de porturi a lui nmap (nmap-services)."
        " Setați TOOL_NMAP_SERVICES cu calea către fișier.",
        "en": "Can't find nmap's port list (nmap-services)."
        " Set TOOL_NMAP_SERVICES to the file's path.",
    },
    "NMAP_FAILED": {
        "ro": "Scanarea nu a reușit. Verificați parola de administrator și că sunteți"
        " conectat la rețeaua dumneavoastră, apoi încercați din nou.",
        "en": "The scan didn't work. Check the admin password and that you're on"
        " your own network, then try again.",
    },
    "NO_LIVE_HOSTS": {
        "ro": "Niciun dispozitiv nu a răspuns în {targets}.",
        "en": "No device answered in {targets}.",
    },
    "IPV6_NOT_SUPPORTED": {
        "ro": "Deocamdată scanarea funcționează doar pentru rețele IPv4.",
        "en": "For now the scan only works on IPv4 networks.",
    },
}


def _scan_text(key: str, lang: str, **values: object) -> str:
    text = _SCAN_TEXT.get(key, _SCAN_TEXT["NMAP_FAILED"])[lang]
    for name, value in values.items():  # str.replace: a value is only ever text
        text = text.replace("{" + name + "}", str(value))
    return text


def scan_command(args: argparse.Namespace) -> int:
    """Guardrail first (FR-02): nothing is scanned unless every check passes."""
    from tool import scan as live
    from tool.content import detect_error_message, file_error_message, refusal_message
    from tool.engine import analyze_file
    from tool.guardrail import Refused, authorize, build_allowlist, extra_ranges_from_env
    from tool.network import DetectError, detect

    # Least privilege (MASTERPLAN §3.7): only the nmap subprocess gets admin rights.
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print(_scan_text("RUN_AS_ROOT", args.lang), file=sys.stderr)
        return 2
    try:
        net = detect()
    except DetectError as exc:
        print(detect_error_message(exc.code, args.lang), file=sys.stderr)
        return 1
    try:
        allowlist = build_allowlist(net.subnet, extra_ranges_from_env())
        networks = authorize(args.targets or [net.subnet], allowlist, args.confirm)
    except Refused as exc:
        print(refusal_message(exc.code, exc.target, args.lang), file=sys.stderr)
        print(f"({exc.code})", file=sys.stderr)
        return 3
    targets = ", ".join(str(n) for n in networks)
    print(_scan_text("START", args.lang, targets=targets), flush=True)
    print(_scan_text("SELF_SKIPPED", args.lang, address=net.address), flush=True)
    try:
        path = live.run_scan(
            networks, runner=live.run_nmap, scans_dir=args.scans_dir, exclude=[net.address]
        )
    except live.ScanError as exc:
        print(_scan_text(exc.code, args.lang, targets=targets), file=sys.stderr)
        print(f"({exc.code}{': ' + exc.detail if exc.detail else ''})", file=sys.stderr)
        return 4
    result = analyze_file(path)  # unprivileged, the same engine as `tool analyze`
    if result.status != "ok":
        code = result.error["code"]
        print(f"{path}: {file_error_message(code, args.lang)} ({code})", file=sys.stderr)
        save_and_alert([result], args.lang)
        return 1
    print(
        _scan_text("DONE", args.lang, path=path, score=result.score, findings=len(result.findings))
    )
    save_and_alert([result], args.lang)
    return 0


def analyze_command(args: argparse.Namespace) -> int:
    from tool.content import file_error_message
    from tool.engine.device import load_salt
    from tool.export import analyze_folder

    folder: Path = args.folder
    if not folder.is_dir():
        print(f"{folder}: not a folder", file=sys.stderr)
        return 2
    json_dir = args.out / "json" if args.json else None
    # History keys devices with the private local salt; CSV-only runs never need it.
    salt = load_salt() if args.save else None
    report = analyze_folder(folder, args.out, json_dir=json_dir, salt=salt)
    for file, code in report.errors:  # a broken file is reported, never fatal
        print(f"{file}: {file_error_message(code, args.lang)} ({code})", file=sys.stderr)
    print(
        f"{report.files} files, {report.findings} findings, {len(report.errors)} unreadable"
        f" -> {args.out / 'findings.csv'}, {args.out / 'scores.csv'}"
    )
    if args.save:
        save_and_alert(report.results, args.lang)
    return 0


def save_and_alert(results: list, lang: str) -> None:
    """Store every result in the history (unreadable ones as error rows, which are never
    compared) and print what appeared since the previous readable scan."""
    from tool.content import alert_message
    from tool.history import History

    history = History()
    ids = [history.add(r) for r in results]
    print(f"saved {len(ids)} scans to the local history")
    readable = [i for i, r in zip(ids, results, strict=True) if r.status == "ok"]
    if not readable:
        return
    newest = max(readable, key=[s.id for s in history.scans()].index)
    for alert in history.alerts_for(newest):
        text = alert_message(alert.code, alert.ip, alert.port, alert.protocol, lang)
        print(text, f"({alert.code})")


def detect_command(args: argparse.Namespace) -> int:
    from tool.content import detect_error_message
    from tool.network import DetectError, detect

    try:
        net = detect()
    except DetectError as exc:
        message = detect_error_message(exc.code, args.lang)
        if args.json:
            print(json.dumps({"error": {"code": exc.code, "detail": exc.detail}}))
        else:
            print(message, file=sys.stderr)
            if exc.detail:
                print(f"({exc.code}: {exc.detail})", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(asdict(net)))
        return 0
    labels = _DETECT_LABELS[args.lang]
    for label, value in zip(
        labels, (net.interface, net.address, net.subnet, net.gateway), strict=True
    ):
        print(f"{label}: {value}")
    return 0


def serve(args: argparse.Namespace) -> int:
    # Least privilege (MASTERPLAN §3.7): only the live scan step may run as root.
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print(
            "Refusing to start the web interface as root. Run it as a normal user.",
            file=sys.stderr,
        )
        return 2
    import uvicorn

    from tool.ai.explain import Explainer
    from tool.ai.provider import provider_from_env
    from tool.config import data_dir
    from tool.web.app import create_app, load_json_file

    # The provider comes from LLM_PROVIDER / LLM_API_KEY; with none set, AI stays off.
    # Cache and rejection log are local data (NFR-02), never committed.
    explainer = Explainer(
        provider_from_env(),
        cache_dir=data_dir() / "ai_cache",
        rejection_log=data_dir() / "ai_rejections.jsonl",
    )
    from tool.history import History

    result_path = args.result
    app = create_app(
        lambda: load_json_file(result_path) if result_path else None,
        explainer=explainer,
        history=History(),  # local SQLite in the data folder (#21), read by /history
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "serve":
        return serve(args)
    if args.command == "scan":
        return scan_command(args)
    if args.command == "analyze":
        return analyze_command(args)
    if args.command == "detect":
        return detect_command(args)
    _help, issue = COMMANDS[args.command]
    where = f" (see issue #{issue})" if issue else ""
    print(f"'{args.command}' is not implemented yet{where}.", file=sys.stderr)
    return 2
