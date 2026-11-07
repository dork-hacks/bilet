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

# Device levels on the network map (#170): the worst problem a device has. The icon and
# the label are always drawn with the colour, so colour is never the only signal.
MAP_LEVELS = {
    "high": {"icon": "✕", "ro": "Risc ridicat", "en": "High risk"},
    "medium": {"icon": "!", "ro": "Risc mediu", "en": "Medium risk"},
    "low": {"icon": "↓", "ro": "Risc scăzut", "en": "Low risk"},
    "none": {"icon": "✓", "ro": "Nicio problemă", "en": "No problems"},
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
    # Network map on the home screen (#170).
    "map_heading": {"ro": "Harta rețelei tale", "en": "Your network map"},
    "map_intro": {
        "ro": (
            "Harta grupează dispozitivele în jurul routerului; liniile nu sunt cabluri reale. "
            "Culoarea, semnul și cuvintele arată cât de gravă este o problemă."
        ),
        "en": (
            "The map groups devices around your router; the lines are not real cables. "
            "The colour, sign and words show how serious a problem is."
        ),
    },
    "map_how": {
        "ro": "Trage pentru rotire. Alege un dispozitiv pentru detalii.",
        "en": "Drag to explore. Select a device for details.",
    },
    "map_fullscreen": {"ro": "Ecran complet", "en": "Full screen"},
    "map_exit_fullscreen": {"ro": "Închide ecranul complet", "en": "Exit full screen"},
    "map_focus": {"ro": "Arată dispozitivul de aproape", "en": "Zoom to this device"},
    "map_selected": {"ro": "Dispozitiv selectat", "en": "Selected device"},
    "map_inspector": {"ro": "Detalii și dispozitive", "en": "Device details and search"},
    "map_search": {"ro": "Găsește un dispozitiv", "en": "Find a device"},
    "map_search_hint": {"ro": "Nume, adresă sau tip", "en": "Name, address or type"},
    "map_count": {"ro": "{shown} din {total} dispozitive", "en": "{shown} of {total} devices"},
    "map_no_matches": {
        "ro": "Niciun dispozitiv găsit. Încearcă alt nume sau adresă.",
        "en": "No devices found. Try another name or address.",
    },
    "map_previous": {"ro": "Pagina anterioară", "en": "Previous devices"},
    "map_next": {"ro": "Pagina următoare", "en": "Next devices"},
    "map_keys": {
        "ro": "Cu tastatura: săgețile rotesc harta, iar + și - o măresc sau o micșorează.",
        "en": "With the keyboard: the arrow keys turn the map, and + and - zoom in and out.",
    },
    "map_canvas_label": {
        "ro": "Harta 3D a rețelei tale. Alege un dispozitiv din butoanele de pe hartă.",
        "en": "3D map of your network. Pick a device from the buttons on the map.",
    },
    "map_legend": {"ro": "Ce înseamnă culorile", "en": "What the colours mean"},
    "map_view_3d": {"ro": "Hartă 3D", "en": "3D map"},
    "map_view_list": {"ro": "Listă simplă", "en": "Simple list"},
    "map_view_label": {"ro": "Cum vezi harta", "en": "How to show the map"},
    "map_hub": {"ro": "În mijloc:", "en": "In the middle:"},
    "map_hub_virtual": {"ro": "Wi-Fi-ul tău de acasă", "en": "Your home Wi-Fi"},
    "map_linked": {"ro": "Legate de el:", "en": "Linked to it:"},
    "map_most_dangerous": {"ro": "Cel mai periculos", "en": "Most dangerous"},
    "map_ip": {"ro": "Adresa în rețea:", "en": "Network address:"},
    "map_mac": {"ro": "Adresă hardware:", "en": "Hardware address:"},
    "map_name": {"ro": "Nume:", "en": "Name:"},
    "map_no_findings": {
        "ro": "Nu am găsit probleme la acest dispozitiv.",
        "en": "We found no problems on this device.",
    },
    "map_go_problems": {
        "ro": "Vezi problemele și cum le rezolvi",
        "en": "See the problems and how to fix them",
    },
    "map_go_device": {"ro": "Vezi dispozitivul în listă", "en": "See this device in the list"},
    "map_reset": {"ro": "Pune harta la loc", "en": "Reset the map"},
    "map_zoom_in": {"ro": "Mărește harta", "en": "Zoom in"},
    "map_zoom_out": {"ro": "Micșorează harta", "en": "Zoom out"},
    "map_pick": {
        "ro": "Apasă pe un dispozitiv de pe hartă ca să vezi detaliile aici.",
        "en": "Press a device on the map to see its details here.",
    },
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
    # Followed by the CIS Controls and OWASP IoT Top 10 reference codes (#66).
    "standards": {"ro": "Standarde de securitate:", "en": "Security standards:"},
    # Shown with AI on: how often the safety check replaced an AI answer (MASTERPLAN §5.3).
    "ai_blocked": {
        "ro": "Răspunsuri AI blocate de verificarea de siguranță: {n}",
        "en": "AI answers blocked by the safety check: {n}",
    },
    # "Open a scan file" form on the home screen (#92). The file is checked, never saved.
    "open_heading": {"ro": "Deschide un fișier de verificare", "en": "Open a scan file"},
    "open_label": {"ro": "Alege un fișier nmap XML", "en": "Choose an nmap XML file"},
    "open_hint": {
        "ro": "Îl verificăm pe acest calculator. Nu îl păstrăm în istoric.",
        "en": "We check it on this computer. We don't keep it in your history.",
    },
    "open_button": {"ro": "Verifică fișierul", "en": "Check the file"},
    "open_showing": {
        "ro": "Vezi rezultatul pentru fișierul pe care l-ai deschis.",
        "en": "You are looking at the result for the file you opened.",
    },
    "open_back": {"ro": "Înapoi la ultima verificare", "en": "Back to the latest check"},
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
    # Summary and Q&A (#50). The "can't tell" sentence is shown whenever the scan
    # evidence doesn't cover a question, and whenever an AI answer is rejected.
    "ai_summary_intro": {"ro": "Ordinea recomandată:", "en": "What to do, in order:"},
    "plan_heading": {"ro": "Planul tău", "en": "Your plan"},
    "ask_heading": {"ro": "Întreabă despre rețeaua ta", "en": "Ask about your network"},
    "ask_label": {"ro": "Întrebarea ta", "en": "Your question"},
    "ask_hint": {
        "ro": "De exemplu: E sigur că imprimanta mea are portul 9100 deschis?",
        "en": "For example: Is it safe that my printer has port 9100 open?",
    },
    "chat_welcome": {
        "ro": "Sunt aici să te ajut să înțelegi verificarea rețelei tale.",
        "en": "I'm here to help you understand your network check.",
    },
    "chat_off": {
        "ro": "Asistentul AI este oprit. Îți arăt pașii standard, fără să trimit date.",
        "en": "The AI assistant is off. Here are the standard steps, without sending data.",
    },
    "chat_first": {"ro": "Ce să repar prima dată?", "en": "What should I fix first?"},
    "chat_device": {
        "ro": "Care este cel mai periculos dispozitiv?",
        "en": "Which device needs the most attention?",
    },
    "chat_wait": {"ro": "Pregătesc răspunsul…", "en": "Preparing your answer…"},
    "chat_error": {
        "ro": "Răspunsul nu a ajuns. Încearcă din nou.",
        "en": "The answer didn't arrive. Please try again.",
    },
    "ask_button": {"ro": "Întreabă", "en": "Ask"},
    "ask_you_asked": {"ro": "Ai întrebat:", "en": "You asked:"},
    "ask_answer": {"ro": "Răspuns:", "en": "Answer:"},
    "ai_summary_nothing": {
        "ro": "Verificarea nu a găsit nimic de reparat. Nu trebuie să faci nimic acum.",
        "en": "The scan found nothing to fix. You don't need to do anything right now.",
    },
    "ai_cant_tell": {
        "ro": "Scanarea nu îmi poate spune asta. Uită-te la lista de probleme de mai jos.",
        "en": "The scan can't tell me that. Please look at the list of problems below.",
    },
    "ai_question_needs_ai": {
        "ro": (
            "Întrebările au nevoie de explicațiile cu AI pornite. "
            "Lista de mai jos arată tot ce a găsit scanarea."
        ),
        "en": (
            "Questions need the AI explanations turned on. "
            "The list below shows everything the scan found."
        ),
    },
    # Change alerts on the home screen (#78). The alert sentences are in texts.ALERTS.
    "alerts_heading": {
        "ro": "Ce este nou de la verificarea anterioară",
        "en": "What's new since the previous check",
    },
    # History screen (#65): score trend, compare two checks, delete my history.
    "history_link": {"ro": "Vezi istoricul verificărilor", "en": "See your check history"},
    "history_title": {"ro": "Istoricul verificărilor", "en": "Check history"},
    "back_home": {"ro": "Înapoi la pagina principală", "en": "Back to the home page"},
    # "Every risk explained" page (#83): all catalog codes, read from tool.content only.
    "risks_link": {
        "ro": "Toate riscurile pe care le verificăm",
        "en": "Every risk we check for",
    },
    "risks_title": {"ro": "Riscurile pe care le verificăm", "en": "The risks we check for"},
    "risks_intro": {
        "ro": (
            "Aici sunt toate problemele pe care le poate găsi verificarea, de la cea mai "
            "gravă la cea mai ușoară, cu ce înseamnă și cum le rezolvi."
        ),
        "en": (
            "These are all the problems the check can find, from the most serious to the "
            "least, with what each one means and how to fix it."
        ),
    },
    "risk_more": {"ro": "Mai multe despre acest risc", "en": "More about this risk"},
    "history_off": {
        "ro": "Istoricul nu este pornit pe acest calculator.",
        "en": "History is not turned on on this computer.",
    },
    "history_empty": {
        "ro": "Încă nu ai nicio verificare salvată. După prima verificare, o vei vedea aici.",
        "en": "You have no saved checks yet. After your first check, you will see it here.",
    },
    "history_one": {
        "ro": (
            "Ai o singură verificare salvată. După ce repari ceva, fă încă o verificare "
            "ca să vezi ce s-a schimbat."
        ),
        "en": (
            "You have only one saved check. After you fix something, run another check "
            "to see what changed."
        ),
    },
    "history_no_time": {"ro": "Oră necunoscută", "en": "Unknown time"},
    "history_unreadable": {"ro": "Nu a putut fi citită", "en": "Could not be read"},
    "trend_heading": {"ro": "Cum s-a schimbat scorul", "en": "How your score changed"},
    "trend_up": {
        "ro": "Scorul a crescut de la {a} la {b}.",
        "en": "Your score went up from {a} to {b}.",
    },
    "trend_down": {
        "ro": "Scorul a scăzut de la {a} la {b}.",
        "en": "Your score went down from {a} to {b}.",
    },
    "trend_same": {
        "ro": "Scorul a rămas {b}.",
        "en": "Your score stayed at {b}.",
    },
    "chart_label": {
        "ro": "Graficul scorului, de la cea mai veche la cea mai nouă verificare",
        "en": "Score chart, from the oldest check to the newest",
    },
    "scans_heading": {"ro": "Verificările tale", "en": "Your checks"},
    "col_when": {"ro": "Când", "en": "When"},
    "col_file": {"ro": "Fișier", "en": "File"},
    "col_score": {"ro": "Scor", "en": "Score"},
    "col_state": {"ro": "Stare", "en": "State"},
    "compare_heading": {"ro": "Compară două verificări", "en": "Compare two checks"},
    "compare_before": {"ro": "Înainte", "en": "Before"},
    "compare_after": {"ro": "După", "en": "After"},
    "compare_button": {"ro": "Compară", "en": "Compare"},
    "compare_same": {
        "ro": "Alege două verificări diferite ca să le compari.",
        "en": "Choose two different checks to compare them.",
    },
    "diff_score_up": {
        "ro": "Scorul a crescut de la {a} la {b}.",
        "en": "The score went up from {a} to {b}.",
    },
    "diff_score_down": {
        "ro": "Scorul a scăzut de la {a} la {b}.",
        "en": "The score went down from {a} to {b}.",
    },
    "diff_score_same": {"ro": "Scorul a rămas {b}.", "en": "The score stayed at {b}."},
    "diff_unchanged": {
        "ro": "Nu s-a schimbat nimic între aceste două verificări.",
        "en": "Nothing changed between these two checks.",
    },
    "diff_resolved": {"ro": "Probleme rezolvate", "en": "Problems you fixed"},
    "diff_new_findings": {"ro": "Probleme noi", "en": "New problems"},
    "diff_new_devices": {"ro": "Dispozitive noi", "en": "New devices"},
    "diff_removed_devices": {
        "ro": "Dispozitive care nu mai apar",
        "en": "Devices that are no longer there",
    },
    "diff_opened": {"ro": "Porturi deschise acum", "en": "Ports that are now open"},
    "diff_closed": {"ro": "Porturi închise", "en": "Ports that are now closed"},
    "delete_heading": {"ro": "Șterge istoricul meu", "en": "Delete my history"},
    "delete_note": {
        "ro": (
            "Șterge toate verificările salvate pe acest calculator, plus explicațiile AI "
            "păstrate. Nu se poate anula."
        ),
        "en": (
            "This deletes every check saved on this computer, and the saved AI "
            "explanations. It can't be undone."
        ),
    },
    "delete_button": {"ro": "Șterge istoricul", "en": "Delete my history"},
    "delete_confirm": {
        "ro": "Sigur vrei să ștergi tot istoricul? Nu îl vei mai putea recupera.",
        "en": "Are you sure you want to delete all your history? You can't get it back.",
    },
    "delete_yes": {"ro": "Da, șterge tot", "en": "Yes, delete everything"},
    "delete_no": {"ro": "Nu, păstrează istoricul", "en": "No, keep my history"},
    "deleted_done": {"ro": "Istoricul tău a fost șters.", "en": "Your history was deleted."},
}

LANG_NAMES = {"ro": "Română", "en": "English"}
