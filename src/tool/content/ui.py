"""Romanian and English labels for the web interface (area:content).

Finding texts live in texts.py. These are the short labels around them: the score
band, the home-screen sentence and the page chrome. Placeholders use {name} and are
filled with str.replace by the caller, so braces in scan data are only ever text.
"""

# Score bands for the traffic light (FR-09). The icon and the label always appear
# next to the colour, so colour is never the only signal (WCAG 1.4.1).
SCORE_BANDS = {
    "good": {
        "icon": "✓",
        "ro": "Rețea în siguranță",
        "en": "Network looks safe",
    },
    "warn": {
        "icon": "!",
        "ro": "Are nevoie de atenție",
        "en": "Needs attention",
    },
    "bad": {
        "icon": "✕",
        "ro": "Rețea în pericol",
        "en": "Network at risk",
    },
}

UI = {
    "page_title": {"ro": "Siguranța rețelei de acasă", "en": "Home network safety"},
    "score_heading": {"ro": "Scorul rețelei tale", "en": "Your network score"},
    "score_out_of": {"ro": "din 100", "en": "out of 100"},
    "most_dangerous": {"ro": "Cel mai periculos dispozitiv:", "en": "Most dangerous device:"},
    "do_first": {"ro": "Fă asta mai întâi:", "en": "Do this first:"},
    "nothing_to_fix": {
        "ro": "Nu am găsit nicio problemă. Nu trebuie să faci nimic acum.",
        "en": "We found no problems. There is nothing you need to do right now.",
    },
    "no_scan": {
        "ro": "Încă nu există nicio verificare. Pornește o verificare a rețelei tale.",
        "en": "There is no check yet. Start a check of your network.",
    },
    "error_heading": {
        "ro": "Nu am putut citi această verificare",
        "en": "We could not read this check",
    },
    "scan_file": {"ro": "Fișier:", "en": "File:"},
    "language": {"ro": "Limba", "en": "Language"},
    "device_at": {"ro": "{device} la adresa {ip}", "en": "{device} at {ip}"},
    "points": {"ro": "{n} puncte de risc", "en": "{n} risk points"},
}

LANG_NAMES = {"ro": "Română", "en": "English"}
