"""Human CLI text; flags, paths and machine exports are never translated."""

import re

TEXT = {
    "description": (
        "un instrument pentru securitatea rețelei de acasă",
        "a home network security checker",
    ),
    "analyze": (
        "analizează un dosar cu fișiere XML nmap și scrie findings.csv / scores.csv",
        "analyse a folder of nmap XML files and write findings.csv / scores.csv",
    ),
    "detect": (
        "arată rețeaua la care este conectat calculatorul",
        "show the network this computer is connected to",
    ),
    "scan": (
        "verifică propria rețea (necesită --confirm și drepturi de administrator)",
        "scan your own network (needs --confirm and admin rights)",
    ),
    "serve": ("pornește interfața web", "start the web interface"),
    "help": ("arată acest ajutor și închide programul", "show this help message and exit"),
    "version": ("arată versiunea și închide programul", "show program's version number and exit"),
    "lang": (
        "limba mesajelor și a ajutorului (implicit: ro; ultima valoare are prioritate)",
        "message and help language (default: ro; last value wins)",
    ),
    "positionals": ("argumente poziționale", "positional arguments"),
    "options": ("opțiuni", "options"),
    "usage": ("utilizare: ", "usage: "),
    "error": ("eroare", "error"),
    "result": (
        "arată acest ScanResult JSON în locul ultimei verificări salvate",
        "show this ScanResult JSON, not the latest saved scan",
    ),
    "host": ("implicit: doar acest calculator", "default: this computer only"),
    "port": ("portul interfeței web (implicit: 8000)", "web interface port (default: 8000)"),
    "targets": (
        "adrese sau intervale (implicit: subrețeaua conectată)",
        "addresses or ranges (default: the connected subnet)",
    ),
    "confirm": ("confirmă că aceasta este propria rețea", "confirm this is your own network"),
    "scans_dir": (
        "unde se salvează XML nmap (implicit: scans/, ignorat de git)",
        "where to save the nmap XML (default: scans/, git-ignored)",
    ),
    "folder": ("dosar cu fișiere XML nmap", "folder with nmap XML files"),
    "out": ("unde se scriu fișierele CSV", "where to write the CSVs"),
    "json_results": (
        "scrie și un ScanResult JSON pentru fiecare fișier",
        "also write one ScanResult JSON per file",
    ),
    "save": (
        "salvează verificările și în istoricul local",
        "also store the scans in the local history",
    ),
    "json": ("ieșire pentru procesare automată", "machine-readable output"),
    "not_folder": ("nu este un dosar", "not a folder"),
    "totals": (
        "{files} fișiere, {findings} constatări, {errors} imposibil de citit",
        "{files} files, {findings} findings, {errors} unreadable",
    ),
    "saved": (
        "S-au salvat {count} verificări în istoricul local",
        "saved {count} scans to the local history",
    ),
    "serve_root": (
        "Interfața web nu poate porni ca root. Pornește-o ca utilizator obișnuit.",
        "Refusing to start the web interface as root. Run it as a normal user.",
    ),
}


def cli_text(key: str, lang: str, **values: object) -> str:
    return TEXT[key][lang == "en"].format(**values)


# Match argparse's templates, leaving user input (even English-looking paths) intact.
_ERROR_PATTERNS = (
    (r"argument (.*?): (.*)", "argumentul {0}: {1}"),
    (r"invalid choice: (.*?) \(choose from (.*)\)", "valoare nevalidă: {0} (alege dintre {1})"),
    (r"the following arguments are required: (.*)", "următoarele argumente sunt obligatorii: {0}"),
    (r"unrecognized arguments: (.*)", "argumente nerecunoscute: {0}"),
    (r"expected one argument", "se așteaptă un argument"),
    (r"ignored explicit argument (.*)", "valoare explicită neacceptată: {0}"),
    (r"invalid int value: (.*)", "număr întreg nevalid: {0}"),
    (r"ambiguous option: (.*?) could match (.*)", "opțiune ambiguă: {0}; variante posibile: {1}"),
)


def parser_error(message: str, lang: str) -> str:
    if lang == "en":
        return message
    for pattern, template in _ERROR_PATTERNS:
        match = re.fullmatch(pattern, message)
        if match:
            groups = list(match.groups())
            if pattern == _ERROR_PATTERNS[0][0]:
                groups[1] = parser_error(groups[1], lang)
            return template.format(*groups)
    return "Argumente nevalide."
