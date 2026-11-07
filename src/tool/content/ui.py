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
    # Devices and findings list (#55)
    "devices_heading": {"ro": "Dispozitivele tale", "en": "Your devices"},
    "devices_intro": {
        "ro": "Cel mai periculos dispozitiv este primul. Rezolvă problemele de sus în jos.",
        "en": "The most dangerous device comes first. Fix the problems from top to bottom.",
    },
    "hardware_address": {"ro": "Adresă hardware:", "en": "Hardware address:"},
    "device_name": {"ro": "Nume:", "en": "Name:"},
    "port": {"ro": "Port {port}", "en": "Port {port}"},
    "how_to_fix": {"ro": "Cum rezolvi:", "en": "How to fix it:"},
    "no_problems": {"ro": "Nu am găsit probleme", "en": "No problems found"},
    "safe_devices": {
        "ro": "Dispozitive fără probleme ({n})",
        "en": "Devices with no problems ({n})",
    },
    "why": {"ro": "De ce contează:", "en": "Why it matters:"},
    "explained_by_ai": {"ro": "Explicat de AI", "en": "Explained by AI"},
    "standard_explanation": {"ro": "Explicație standard", "en": "Standard explanation"},
    "ai_heading": {"ro": "Explicații cu AI", "en": "AI explanations"},
    "ai_on_state": {
        "ro": "Explicațiile cu AI sunt pornite.",
        "en": "AI explanations are on.",
    },
    "ai_off_state": {
        "ro": "Explicațiile cu AI sunt oprite.",
        "en": "AI explanations are off.",
    },
    "ai_turn_on": {"ro": "Pornește explicațiile cu AI", "en": "Turn on AI explanations"},
    "ai_turn_off": {"ro": "Oprește explicațiile cu AI", "en": "Turn off AI explanations"},
    "ai_data_note": {
        "ro": (
            "Dacă le pornești, trimitem unui serviciu AI doar tipul problemelor, numerele "
            "porturilor, numele și versiunea programelor și tipul dispozitivului. "
            "Nu trimitem niciodată adrese MAC, adrese IP sau numele dispozitivelor."
        ),
        "en": (
            "If you turn them on, we send an AI service only the problem types, port "
            "numbers, program names and versions, and the device type. "
            "We never send MAC addresses, IP addresses or device names."
        ),
    },
    "ai_not_set_up": {
        "ro": "AI nu este configurat pe acest calculator, așa că vezi explicațiile standard.",
        "en": "AI is not set up on this computer, so you see the standard explanations.",
    },
}

LANG_NAMES = {"ro": "Română", "en": "English"}
