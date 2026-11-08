# ruff: noqa: E501
"""Hand-written Romanian and English texts (MASTERPLAN §5.2, FR-07, FR-08).

This module is data only. The UI always shows these texts, and the AI layer falls
back to them. Rules for editing:
- Write for parents and grandparents: plain words, no unexplained jargon.
- Explanations: at most 2 sentences per language. Fix steps: 1 to 5, the same
  number in both languages.
- Each catalog code marks exactly one fixing action with the localized prefix
  from device_steps.FIX_PREFIXES. Password advice alone does not close a service.
- Never invent menu paths for a specific router or device model.
- When a text means our app, write "{name}" (filled in from DISPLAY_NAME at the end
  of this file). "programul" in a fix step means the device's software and stays.
- Romanian uses comma-below diacritics (ș, ț), never the cedilla forms (ş, ţ),
  and the polite form ("dumneavoastră").
tests/test_content.py enforces these rules.
"""

from tool.config import DISPLAY_NAME

LANGS = ("ro", "en")

# Keyed by catalog code (brief, Part B; docs/contracts/data-model.md).
# `cis` lists CIS Controls v8 safeguards, `owasp_iot` lists OWASP IoT Top 10 (2018) items.
FINDINGS: dict[str, dict] = {
    "TELNET_OPEN": {
        "title": {
            "ro": "Control de la distanță fără criptare (Telnet)",
            "en": "Remote control without encryption (Telnet)",
        },
        "explanation": {
            "ro": "Acest dispozitiv permite conectarea și controlul de la distanță prin Telnet, care trimite parolele ca text simplu, ușor de citit. Oricine este conectat la rețeaua dumneavoastră Wi-Fi ar putea citi parola și prelua controlul dispozitivului.",
            "en": "This device lets people log in and control it over Telnet, which sends passwords as plain, readable text. Anyone on your Wi-Fi could read the password and take over the device.",
        },
        "steps": {
            "ro": [
                "Deschideți setările dispozitivului (aplicația lui sau pagina web indicată în manual).",
                "Acesta este pasul care rezolvă problema: căutați o opțiune numită Telnet sau „acces la distanță” și dezactivați-o.",
                "Dacă nu găsiți această opțiune, verificați dacă există o actualizare de software pentru dispozitiv și instalați-o.",
                "Schimbați parola dispozitivului cu una lungă, pe care nu o folosiți în altă parte.",
                "Dacă Telnet tot nu poate fi oprit, întrebați vânzătorul sau un tehnician dacă dispozitivul ar trebui înlocuit.",
            ],
            "en": [
                "Open the device's settings (its app, or the web page shown in its manual).",
                "This is the step that fixes it: look for an option called Telnet or “remote access” and turn it off.",
                "If you can't find that option, check for a software update for the device and install it.",
                "Change the device's password to a long one that you don't use anywhere else.",
                "If Telnet still can't be turned off, ask the seller or a technician whether the device should be replaced.",
            ],
        },
        "cis": ["4.8", "3.10"],
        "owasp_iot": ["I2", "I7"],
    },
    "RDP_EXPOSED": {
        "title": {
            "ro": "Desktop la distanță (Remote Desktop) este pornit",
            "en": "Windows Remote Desktop is turned on",
        },
        "explanation": {
            "ro": "Acest calculator acceptă conexiuni Remote Desktop, prin care cineva îi poate vedea și controla ecranul de pe alt dispozitiv. Atacatorii încearcă des să ghicească parolele acestor conexiuni, așa că lăsați funcția oprită dacă nu o folosiți.",
            "en": "This computer accepts Remote Desktop connections, which let someone see and control its screen from another device. Attackers often try to guess the passwords for these connections, so keep it off unless you use it.",
        },
        "steps": {
            "ro": [
                "Pe calculator, deschideți Setări și căutați „Desktop la distanță” (Remote Desktop).",
                "Acesta este pasul care rezolvă problema: dezactivați Desktop la distanță dacă nimeni nu are nevoie să controleze acest calculator de pe alt dispozitiv.",
                "Dacă îl folosiți, asigurați-vă că contul Windows are o parolă lungă și unică.",
                "Instalați toate actualizările Windows disponibile.",
            ],
            "en": [
                "On the computer, open Settings and search for “Remote Desktop”.",
                "This is the step that fixes it: turn Remote Desktop off if nobody needs to control this computer from another device.",
                "If you do use it, make sure the Windows account has a long, unique password.",
                "Install all available Windows updates.",
            ],
        },
        "cis": ["4.8"],
        "owasp_iot": ["I2"],
    },
    "VNC_EXPOSED": {
        "title": {
            "ro": "Partajarea ecranului (VNC) este pornită",
            "en": "Screen sharing (VNC) is turned on",
        },
        "explanation": {
            "ro": "Pe acest dispozitiv rulează VNC, un program prin care cineva îi poate vedea și controla ecranul de pe alt dispozitiv. VNC are adesea o parolă slabă sau deloc, așa că oricine din rețeaua Wi-Fi ar putea intra.",
            "en": "This device runs VNC, a program that lets someone see and control its screen from another device. VNC often has a weak password or none at all, so anyone on your Wi-Fi might get in.",
        },
        "steps": {
            "ro": [
                "Găsiți programul de partajare a ecranului sau VNC pe dispozitiv (în setări sau în lista de aplicații instalate).",
                "Acesta este pasul care rezolvă problema: opriți-l sau dezinstalați-l dacă nu aveți nevoie de el.",
                "Dacă aveți nevoie de el, setați în program o parolă lungă și unică.",
                "Actualizați programul la cea mai nouă versiune.",
            ],
            "en": [
                "Find the screen-sharing or VNC program on the device (in its settings or in the list of installed apps).",
                "This is the step that fixes it: turn it off or uninstall it if you don't need it.",
                "If you need it, set a long, unique password in the program.",
                "Update the program to its newest version.",
            ],
        },
        "cis": ["4.8"],
        "owasp_iot": ["I1", "I2"],
    },
    "DB_EXPOSED": {
        "title": {
            "ro": "O bază de date poate fi accesată din rețea",
            "en": "A database can be reached on your network",
        },
        "explanation": {
            "ro": "Pe acest dispozitiv rulează o bază de date (un program care păstrează informații), la care se pot conecta direct alte dispozitive din rețea. Dacă nu are parolă, oricine din rețeaua Wi-Fi ar putea citi sau șterge ce este stocat în ea.",
            "en": "This device runs a database (a program that stores information) that other devices on your network can connect to directly. If it has no password, anyone on your Wi-Fi could read or delete what is stored in it.",
        },
        "steps": {
            "ro": [
                "Aflați ce program folosește baza de date (de obicei un server de acasă, un dispozitiv de stocare sau un program instalat de un tehnician).",
                "Acesta este pasul care rezolvă problema: în setările acelui program, permiteți conexiuni la baza de date doar de pe același dispozitiv.",
                "Setați o parolă puternică pentru baza de date.",
                "Dacă nu știți la ce folosește baza de date, întrebați persoana care a configurat dispozitivul.",
            ],
            "en": [
                "Find out which program uses the database (often a home server, a storage box or a program installed by a technician).",
                "This is the step that fixes it: in that program's settings, allow database connections only from the same device.",
                "Set a strong password for the database.",
                "If you don't know what the database is for, ask whoever set up the device.",
            ],
        },
        "cis": ["4.4"],
        "owasp_iot": ["I2"],
    },
    "CAMERA_STREAM_EXPOSED": {
        "title": {
            "ro": "Imaginile camerei pot fi urmărite din rețea",
            "en": "Camera video can be watched on your network",
        },
        "explanation": {
            "ro": "Acest dispozitiv transmite imagini video în direct, pe care le pot deschide alte dispozitive din rețea. Dacă transmisia nu are parolă sau are parola din fabrică, oricine din rețeaua Wi-Fi ar putea urmări ce filmează camera.",
            "en": "This device sends a live video stream that other devices on your network can open. If the stream has no password or still has the factory password, anyone on your Wi-Fi could watch what the camera sees.",
        },
        "steps": {
            "ro": [
                "Deschideți aplicația sau pagina de setări a camerei.",
                "Schimbați parola camerei cu una lungă, pe care nu o folosiți în altă parte.",
                "Acesta este pasul care rezolvă problema: dezactivați opțiunea de transmisie video (numită adesea RTSP sau ONVIF) dacă urmăriți camera doar din aplicația ei.",
                "Instalați orice actualizare de software pe care aplicația o oferă pentru cameră.",
                "Asigurați-vă că rețeaua Wi-Fi are o parolă puternică, ca să nu se poată conecta străini.",
            ],
            "en": [
                "Open the camera's app or settings page.",
                "Change the camera's password to a long one that you don't use anywhere else.",
                "This is the step that fixes it: turn off the video stream option (often called RTSP or ONVIF) if you only watch the camera through its own app.",
                "Install any software update that the app offers for the camera.",
                "Make sure your Wi-Fi has a strong password, so strangers can't join it.",
            ],
        },
        "cis": ["4.8", "3.10"],
        "owasp_iot": ["I2", "I6"],
    },
    "OUTDATED_SERVICE": {
        "title": {
            "ro": "Program vechi, cu breșe de securitate cunoscute",
            "en": "Old software with known security holes",
        },
        "explanation": {
            "ro": "Un program de pe acest dispozitiv este o versiune veche, cu breșe de securitate cunoscute public. Atacatorii au unelte gata făcute pentru astfel de breșe, așa că programul trebuie actualizat sau oprit.",
            "en": "A program on this device is an old version with publicly known security holes. Attackers have ready-made tools for such holes, so the program should be updated or turned off.",
        },
        "steps": {
            "ro": [
                "Acesta este pasul care rezolvă problema: verificați dacă există o actualizare de software pentru dispozitiv (în aplicația lui, pe pagina de setări sau pe site-ul producătorului) și instalați-o.",
                "Reporniți dispozitivul după actualizare.",
                "Dacă nu există nicio actualizare, opriți programul vechi sau nu mai folosiți dispozitivul.",
                "Faceți din nou verificarea, ca să confirmați că problema a dispărut.",
            ],
            "en": [
                "This is the step that fixes it: check for a software update for the device (in its app, on its settings page or on the maker's website) and install it.",
                "Restart the device after the update.",
                "If there is no update, turn off the old program or stop using the device.",
                "Run the check again to confirm that the problem is gone.",
            ],
        },
        "cis": ["7.4"],
        "owasp_iot": ["I4", "I5"],
    },
    "FTP_CLEARTEXT": {
        "title": {
            "ro": "Partajare de fișiere fără criptare (FTP)",
            "en": "File sharing without encryption (FTP)",
        },
        "explanation": {
            "ro": "Acest dispozitiv partajează fișiere prin FTP, care trimite parolele și fișierele ca text simplu, ușor de citit. Oricine din rețeaua Wi-Fi le-ar putea citi în timp ce sunt transmise.",
            "en": "This device shares files over FTP, which sends passwords and files as plain, readable text. Anyone on your Wi-Fi could read them while they are being sent.",
        },
        "steps": {
            "ro": [
                "Deschideți setările dispozitivului și găsiți opțiunea FTP sau de partajare a fișierelor.",
                "Acesta este pasul care rezolvă problema: dezactivați FTP dacă nu îl folosiți.",
                "Dacă aveți nevoie să partajați fișiere, alegeți în schimb o variantă criptată (numită adesea SFTP sau FTPS).",
                "Schimbați parola folosită pentru partajarea fișierelor.",
            ],
            "en": [
                "Open the device's settings and find the FTP or file-sharing option.",
                "This is the step that fixes it: turn FTP off if you don't use it.",
                "If you need to share files, choose an encrypted option instead (often called SFTP or FTPS).",
                "Change the password used for file sharing.",
            ],
        },
        "cis": ["3.10", "4.8"],
        "owasp_iot": ["I7"],
    },
    "HTTP_ADMIN_CLEARTEXT": {
        "title": {
            "ro": "Pagină de setări fără criptare",
            "en": "Settings page without encryption",
        },
        "explanation": {
            "ro": "Acest dispozitiv are o pagină de setări sau de autentificare care se deschide fără criptare (http, nu https). Parola pe care o introduceți acolo poate fi citită de oricine din rețeaua Wi-Fi.",
            "en": "This device has a settings or login page that opens without encryption (http, not https). The password you type there can be read by anyone on your Wi-Fi.",
        },
        "steps": {
            "ro": [
                "Acesta este pasul care rezolvă problema: în setările dispozitivului, activați HTTPS sau „conexiune securizată”, apoi opriți accesul HTTP necriptat. Dacă nu există HTTPS, cereți ajutor pentru a opri pagina web necriptată.",
                "Schimbați parola paginii de setări cu una lungă și unică; parola nouă singură nu oprește accesul HTTP necriptat.",
                "Instalați orice actualizare de software oferită pentru dispozitiv.",
                "Dacă dispozitivul are o opțiune de administrare de la distanță prin internet, dezactivați-o.",
            ],
            "en": [
                "This is the step that fixes it: in the device's settings, enable HTTPS or a “secure connection”, then turn off unencrypted HTTP access. If HTTPS is unavailable, ask for help turning off the unencrypted web page.",
                "Change the settings page password to a long, unique one; a new password alone does not turn off unencrypted HTTP access.",
                "Install any software update offered for the device.",
                "If the device has an option for remote management over the internet, turn it off.",
            ],
        },
        "cis": ["3.10", "4.7"],
        "owasp_iot": ["I3", "I7"],
    },
    "SMB_EXPOSED": {
        "title": {
            "ro": "Partajarea de fișiere Windows este pornită",
            "en": "Windows file sharing is turned on",
        },
        "explanation": {
            "ro": "Acest dispozitiv partajează foldere în rețea prin partajarea de fișiere Windows (SMB). Dacă folderele partajate au parole slabe, oricine din rețeaua Wi-Fi v-ar putea deschide, modifica sau șterge fișierele.",
            "en": "This device shares folders on your network with Windows file sharing (SMB). If the shared folders have weak passwords, anyone on your Wi-Fi could open, change or delete your files.",
        },
        "steps": {
            "ro": [
                "Aflați ce foldere partajează acest dispozitiv (căutați „partajare” în setările lui).",
                "Acesta este pasul care rezolvă problema: dezactivați serviciul de partajare de fișiere Windows (SMB) dacă nu aveți nevoie de el; oprirea partajării unui singur folder poate lăsa serviciul pornit.",
                "Asigurați-vă că fiecare folder partajat cere o parolă și că parola este puternică.",
                "Instalați toate actualizările disponibile pentru dispozitiv.",
            ],
            "en": [
                "Find out which folders this device shares (look for “sharing” in its settings).",
                "This is the step that fixes it: turn off the Windows file-sharing service (SMB) if you do not need it; stopping sharing for one folder can leave the service running.",
                "Make sure every shared folder asks for a password, and that the password is strong.",
                "Install all available updates for the device.",
            ],
        },
        "cis": ["4.8", "3.3"],
        "owasp_iot": ["I2"],
    },
    "MQTT_EXPOSED": {
        "title": {
            "ro": "Mesajele dispozitivelor inteligente nu sunt protejate (MQTT)",
            "en": "Smart-home messages are not protected (MQTT)",
        },
        "explanation": {
            "ro": "Pe acest dispozitiv rulează MQTT, un serviciu de mesaje prin care dispozitivele inteligente din casă comunică între ele. Fără parolă, oricine din rețeaua Wi-Fi ar putea citi aceste mesaje sau trimite comenzi false, de exemplu să pornească sau să oprească dispozitive.",
            "en": "This device runs MQTT, a messaging service that smart-home gadgets use to talk to each other. Without a password, anyone on your Wi-Fi could read these messages or send fake commands, for example to turn devices on or off.",
        },
        "steps": {
            "ro": [
                "Deschideți setările hub-ului sau ale aplicației de casă inteligentă și găsiți opțiunea MQTT.",
                "Acesta este pasul care rezolvă problema: dacă nimic din casă nu folosește MQTT, dezactivați-l.",
                "Dacă aveți nevoie de MQTT, activați opțiunea care cere nume de utilizator și parolă, și alegeți o parolă puternică. Parola protejează accesul, dar avertismentul rămâne cât timp serviciul este accesibil din rețea.",
                "Instalați orice actualizare de software oferită pentru hub.",
            ],
            "en": [
                "Open the settings of your smart-home hub or app and find the MQTT option.",
                "This is the step that fixes it: if nothing in your home uses MQTT, turn it off.",
                "If you need MQTT, turn on the option that asks for a username and password, and choose a strong password. The password protects access, but the warning stays while the service is reachable on the network.",
                "Install any software update offered for the hub.",
            ],
        },
        "cis": ["4.8", "3.10"],
        "owasp_iot": ["I2", "I7"],
    },
    "UPNP_EXPOSED": {
        "title": {
            "ro": "Configurarea automată (UPnP) este pornită",
            "en": "Automatic setup (UPnP) is turned on",
        },
        "explanation": {
            "ro": "Acest dispozitiv folosește UPnP, o funcție prin care alte dispozitive îl pot găsi și, în cazul routerelor, pot schimba setările rețelei fără să vă întrebe. Un program periculos ar putea folosi această funcție ca să afle ce dispozitive aveți sau să vă deschidă rețeaua către internet.",
            "en": "This device uses UPnP, a feature that lets other devices find it and, on routers, change network settings without asking you. Harmful software could use it to learn what devices you have or to open your network to the internet.",
        },
        "steps": {
            "ro": [
                "Deschideți setările dispozitivului (pentru router, pagina lui de setări; adresa este de obicei pe o etichetă lipită pe router).",
                "Acesta este pasul care rezolvă problema: găsiți opțiunea UPnP și dezactivați-o.",
                "Dacă ceva nu mai funcționează după aceea, întrebați persoana care v-a configurat rețeaua înainte să o reactivați.",
                "Instalați orice actualizare de software oferită pentru dispozitiv.",
            ],
            "en": [
                "Open the device's settings (for a router, its settings page; the address is usually on a sticker on the router).",
                "This is the step that fixes it: find the UPnP option and turn it off.",
                "If something stops working afterwards, ask whoever set up your network before you turn it back on.",
                "Install any software update offered for the device.",
            ],
        },
        "cis": ["4.8"],
        "owasp_iot": ["I9"],
    },
    "SNMP_EXPOSED": {
        "title": {
            "ro": "Serviciul de informații despre dispozitiv (SNMP) este pornit",
            "en": "Device information service (SNMP) is turned on",
        },
        "explanation": {
            "ro": "Acest dispozitiv răspunde la SNMP, un serviciu care oferă detalii despre dispozitiv și uneori îi poate modifica setările. Multe dispozitive vin cu o parolă implicită pentru acest serviciu (adesea „public”), așa că oricine din rețeaua Wi-Fi le-ar putea citi sau modifica.",
            "en": "This device answers SNMP, a service that gives out details about the device and can sometimes change its settings. Many devices come with a default password for it (often “public”), so anyone on your Wi-Fi might read or change them.",
        },
        "steps": {
            "ro": [
                "Deschideți setările dispozitivului și găsiți opțiunea SNMP.",
                "Acesta este pasul care rezolvă problema: dezactivați SNMP dacă nu îl folosiți (în majoritatea caselor nu este folosit).",
                "Dacă aveți nevoie de el, înlocuiți parola implicită (numită „community string”) cu una lungă și unică.",
                "Instalați orice actualizare de software oferită pentru dispozitiv.",
            ],
            "en": [
                "Open the device's settings and find the SNMP option.",
                "This is the step that fixes it: turn SNMP off if you don't use it (most homes don't).",
                "If you need it, replace the default password (called the “community string”) with a long, unique one.",
                "Install any software update offered for the device.",
            ],
        },
        "cis": ["4.8", "4.7"],
        "owasp_iot": ["I9", "I2"],
    },
    "PRINTER_RAW_EXPOSED": {
        "title": {
            "ro": "Imprimanta acceptă documente de la oricine",
            "en": "The printer accepts print jobs from anyone",
        },
        "explanation": {
            "ro": "Această imprimantă acceptă documente trimise direct prin rețea, fără să verifice cine le trimite. Oricine din rețeaua Wi-Fi ar putea imprima pe ea sau, la unele modele, i-ar putea modifica setările.",
            "en": "This printer accepts documents sent straight over the network without checking who sends them. Anyone on your Wi-Fi could print on it or, on some models, change its settings.",
        },
        "steps": {
            "ro": [
                "Deschideți setările imprimantei (pe ecranul ei sau pe pagina web indicată în manual).",
                "Acesta este pasul care rezolvă problema: dacă imprimați doar de pe câteva calculatoare sau telefoane, dezactivați imprimarea directă (numită adesea JetDirect, RAW sau 9100).",
                "Setați o parolă de administrator pentru imprimantă.",
                "Instalați orice actualizare de software oferită pentru imprimantă.",
            ],
            "en": [
                "Open the printer's settings (on its screen, or on the web page shown in its manual).",
                "This is the step that fixes it: if you only print from a few computers or phones, turn off direct printing (often called JetDirect, RAW or 9100).",
                "Set an administrator password for the printer.",
                "Install any software update offered for the printer.",
            ],
        },
        "cis": ["4.8"],
        "owasp_iot": ["I2", "I9"],
    },
    "UNKNOWN_DEVICE": {
        "title": {
            "ro": "Un dispozitiv pe care nu l-am putut identifica",
            "en": "A device we couldn't identify",
        },
        "explanation": {
            "ro": "Acest dispozitiv nu are nume și nici producător cunoscut, așa că verificarea nu poate spune ce este. Uitați-vă dacă îl recunoașteți, pentru că un dispozitiv necunoscut ar putea fi al unui străin care vă folosește rețeaua Wi-Fi.",
            "en": "This device has no name and no known maker, so the check can't tell what it is. See whether you recognise it, because an unknown device could belong to a stranger using your Wi-Fi.",
        },
        "steps": {
            "ro": [
                "Faceți o listă cu dispozitivele dumneavoastră care folosesc Wi-Fi (telefoane, televizor, boxe, camere, prize inteligente).",
                "Opriți-le pe rând și faceți din nou verificarea, ca să vedeți când dispare dispozitivul necunoscut.",
                "Dacă nu este al dumneavoastră, schimbați parola rețelei Wi-Fi și reconectați doar dispozitivele proprii.",
                "Acesta este pasul care rezolvă problema: dați dispozitivelor proprii un nume clar în setările lor, ca să le recunoașteți ușor data viitoare.",
            ],
            "en": [
                "Make a list of your own devices that use Wi-Fi (phones, TV, speakers, cameras, smart plugs).",
                "Turn them off one at a time and run the check again, to see when the unknown device disappears.",
                "If it isn't yours, change your Wi-Fi password and reconnect only your own devices.",
                "This is the step that fixes it: give your own devices a clear name in their settings, so they are easy to recognise next time.",
            ],
        },
        "cis": ["1.1", "1.2"],
        "owasp_iot": ["I8"],
    },
    "SSH_OPEN": {
        "title": {
            "ro": "Conectarea securizată de la distanță (SSH) este pornită",
            "en": "Secure remote login (SSH) is turned on",
        },
        "explanation": {
            "ro": "Acest dispozitiv acceptă SSH, o metodă criptată prin care tehnicienii se pot conecta la el și îl pot administra de pe alt dispozitiv. Este sigur dacă este protejat de o parolă puternică sau de o cheie de securitate, deci acesta este doar un mesaj informativ.",
            "en": "This device accepts SSH, an encrypted way for technicians to log in and manage it from another device. It is safe when it is protected by a strong password or a security key, so this is for your information only.",
        },
        "steps": {
            "ro": [
                "Dacă nu știți de ce acest dispozitiv acceptă SSH, întrebați persoana care l-a configurat.",
                "Asigurați-vă că autentificarea folosește o parolă lungă și unică sau o cheie de securitate.",
                "Acesta este pasul care rezolvă problema: dezactivați SSH dacă nu are nimeni nevoie de el.",
            ],
            "en": [
                "If you don't know why this device accepts SSH, ask whoever set it up.",
                "Make sure the login uses a long, unique password or a security key.",
                "This is the step that fixes it: turn SSH off if nobody needs it.",
            ],
        },
        "cis": ["4.7", "5.2"],
        "owasp_iot": ["I1"],
    },
}

# Used when a code has no entry (it should never happen; the test checks all 15).
GENERIC_FINDING: dict = {
    "title": {
        "ro": "O posibilă problemă de securitate",
        "en": "A possible security problem",
    },
    "explanation": {
        "ro": "Verificarea a găsit pe acest dispozitiv un serviciu care ar putea fi riscant. Dacă nu știți la ce folosește, întrebați persoana care a configurat dispozitivul.",
        "en": "The check found a service on this device that could be risky. If you don't know what it is for, ask whoever set up the device.",
    },
    "steps": {
        "ro": [
            "Deschideți setările dispozitivului și opriți serviciile pe care nu le folosiți.",
            "Instalați orice actualizare de software oferită pentru dispozitiv.",
        ],
        "en": [
            "Open the device's settings and turn off services you don't use.",
            "Install any software update offered for the device.",
        ],
    },
    "cis": [],
    "owasp_iot": [],
}

SEVERITIES: dict[str, dict[str, str]] = {
    "high": {"ro": "Risc ridicat", "en": "High risk"},
    "medium": {"ro": "Risc mediu", "en": "Medium risk"},
    "low": {"ro": "Risc scăzut", "en": "Low risk"},
    "info": {"ro": "Doar informativ", "en": "For information only"},
}

# Keyed by `device_type_guess` (docs/contracts/data-model.md).
DEVICE_TYPES: dict[str, dict[str, str]] = {
    "router": {"ro": "Router", "en": "Router"},
    "camera": {"ro": "Cameră video", "en": "Camera"},
    "printer": {"ro": "Imprimantă", "en": "Printer"},
    "pc": {"ro": "Calculator", "en": "Computer"},
    "phone": {"ro": "Telefon", "en": "Phone"},
    "tv": {"ro": "Televizor", "en": "TV"},
    "iot_hub": {"ro": "Hub de casă inteligentă", "en": "Smart-home hub"},
    "nas": {"ro": "Dispozitiv de stocare în rețea", "en": "Network storage box"},
    "server": {"ro": "Server", "en": "Server"},
    "unknown": {"ro": "Dispozitiv necunoscut", "en": "Unknown device"},
}

# Keyed by `error.code` for unreadable files (docs/contracts/data-model.md).
FILE_ERRORS: dict[str, dict[str, str]] = {
    "ANALYSIS_FAILED": {
        "ro": "Aplicația nu a putut verifica acest fișier. Celelalte fișiere vor fi verificate.",
        "en": "The app could not check this file. The other files will still be checked.",
    },
    "EMPTY_FILE": {
        "ro": "Acest fișier este gol, deci nu există nimic de verificat.",
        "en": "This file is empty, so there is nothing to check.",
    },
    "TOO_LARGE": {
        "ro": "Acest fișier este prea mare pentru a fi verificat în siguranță, așa că l-am sărit.",
        "en": "This file is too large to check safely, so it was skipped.",
    },
    "NOT_XML": {
        "ro": "Acest fișier este deteriorat sau incomplet, așa că nu poate fi citit.",
        "en": "This file is damaged or incomplete, so it can't be read.",
    },
    "UNSAFE_XML": {
        "ro": "Acest fișier conține elemente care ar putea fi folosite pentru un atac, așa că nu l-am deschis.",
        "en": "This file contains parts that could be used for an attack, so it was not opened.",
    },
    "NOT_NMAP": {
        "ro": "Acest fișier nu este rezultatul unei scanări de rețea, așa că nu poate fi verificat.",
        "en": "This file is not the result of a network scan, so it can't be checked.",
    },
}

GENERIC_FILE_ERROR: dict[str, str] = {
    "ro": "Acest fișier nu poate fi citit.",
    "en": "This file can't be read.",
}

# Shown when a scan's results are written but the local history can't be updated
# (a locked, corrupt or newer database, or a folder that can't be written; #132).
HISTORY_FAILED: dict[str, str] = {
    "ro": "Rezultatele sunt salvate, dar istoricul nu a putut fi actualizat.",
    "en": "Your results are saved, but the history couldn't be updated.",
}

# Guardrail refusals (FR-02). These codes are proposed to the guardrail owner in #18;
# rename them here if #18 settles on others. `{target}` is filled in by the caller.
REFUSALS: dict[str, dict[str, str]] = {
    "PUBLIC_ADDRESS": {
        "ro": "Adresa {target} este pe internet, nu în rețeaua dumneavoastră de acasă. Aplicația {name} verifică doar rețeaua dumneavoastră.",
        "en": "The address {target} is on the internet, not in your home network. The {name} app only checks your own network.",
    },
    "CGNAT_ADDRESS": {
        "ro": "Adresa {target} aparține rețelei operatorului de telefonie mobilă, nu casei dumneavoastră. Aplicația {name} verifică doar rețeaua dumneavoastră.",
        "en": "The address {target} belongs to your mobile operator's network, not to your home. The {name} app only checks your own network.",
    },
    "LOOPBACK_ADDRESS": {
        "ro": "Adresa {target} trimite înapoi la acest calculator, deci nu există nicio rețea de verificat.",
        "en": "The address {target} points back to this computer, so there is no network to check.",
    },
    "LINK_LOCAL_ADDRESS": {
        "ro": "Adresa {target} este o adresă temporară, aleasă automat, nu rețeaua dumneavoastră de acasă.",
        "en": "The address {target} is a temporary, automatically chosen address, not your home network.",
    },
    "MULTICAST_ADDRESS": {
        "ro": "Adresa {target} este folosită pentru mesaje de grup, nu pentru un dispozitiv sau o rețea.",
        "en": "The address {target} is used for group messages, not for a single device or network.",
    },
    "HOSTNAME_NOT_ALLOWED": {
        "ro": "Introduceți o adresă formată din cifre, nu un nume. Un nume poate trimite oriunde, inclusiv pe internet.",
        "en": "Enter an address made of numbers, not a name. A name can point anywhere, including the internet.",
    },
    "RANGE_TOO_LARGE": {
        "ro": "Intervalul {target} este prea mare. Aplicația {name} verifică cel mult 256 de adrese (un /24) o dată.",
        "en": "The range {target} is too large. The {name} app checks at most 256 addresses (a /24) at a time.",
    },
    "OUTSIDE_ALLOWLIST": {
        "ro": "Adresa {target} nu face parte din rețeaua la care este conectat acest calculator. Aplicația {name} verifică doar rețeaua la care este conectat calculatorul.",
        "en": "The address {target} is not part of the network this computer is connected to. The {name} app only checks the network this computer is connected to.",
    },
    "CONFIRM_REQUIRED": {
        "ro": "Aplicația {name} ar verifica {target}. Ca să porniți verificarea, confirmați că aceasta este rețeaua dumneavoastră (în linia de comandă, adăugați --confirm).",
        "en": "The {name} app would check {target}. To start the check, confirm that this is your own network (on the command line, add --confirm).",
    },
    "INVALID_TARGET": {
        "ro": "{target} nu este o adresă de rețea validă.",
        "en": "{target} is not a valid network address.",
    },
}

# Network detection errors (FR-01, `tool detect` in #19). The codes come from
# tool.network; an unknown code is shown as DETECT_FAILED.
DETECT_ERRORS: dict[str, dict[str, str]] = {
    "NO_NETWORK": {
        "ro": "Calculatorul nu pare conectat la nicio rețea. Conectați-l la hotspot și încercați din nou.",
        "en": "This computer doesn't seem to be connected to any network. Connect it to the hotspot and try again.",
    },
    "SEVERAL_NETWORKS": {
        "ro": "Calculatorul este conectat la mai multe rețele în același timp. Lăsați conectat doar hotspot-ul: deconectați cablul de rețea, celelalte rețele Wi-Fi și orice VPN, apoi încercați din nou.",
        "en": "This computer is connected to several networks at once. Leave only the hotspot connected: unplug any network cable, disconnect other Wi-Fi networks and turn off any VPN, then try again.",
    },
    "DETECT_FAILED": {
        "ro": "Nu am putut afla la ce rețea este conectat calculatorul. Verificați că este conectat la hotspot și încercați din nou.",
        "en": "We couldn't work out which network this computer is connected to. Check that it is connected to the hotspot and try again.",
    },
}

# Change alerts (FR-13, #22). The codes come from tool.history.Alert; an unknown code
# is shown as GENERIC_ALERT. {ip}, {port} and {protocol} are filled in as plain text.
ALERTS: dict[str, dict[str, str]] = {
    "NEW_DEVICE": {
        "ro": "Un dispozitiv nou s-a conectat la rețeaua dumneavoastră: {ip}. Dacă nu îl recunoașteți, schimbați parola rețelei Wi-Fi.",
        "en": "A new device joined your network: {ip}. If you don't recognise it, change your Wi-Fi password.",
    },
    "NEW_OPEN_PORT": {
        "ro": "Dispozitivul {ip} are un serviciu nou pornit (portul {port}/{protocol}). Dacă nu ați instalat sau pornit nimic nou pe el, verificați ce s-a schimbat.",
        "en": "The device at {ip} has a new service turned on (port {port}/{protocol}). If you didn't install or turn on anything new on it, check what changed.",
    },
}

GENERIC_ALERT: dict[str, str] = {
    "ro": "Ceva s-a schimbat în rețeaua dumneavoastră de la verificarea anterioară.",
    "en": "Something changed on your network since the previous check.",
}

GENERIC_REFUSAL: dict[str, str] = {
    "ro": "Aplicația {name} a refuzat să verifice {target}. Verifică doar rețeaua dumneavoastră.",
    "en": "The {name} app refused to check {target}. It only checks your own network.",
}

# Live scan messages (`tool scan`, #20, #94 and #107). RUN_AS_ROOT, START, HOSTS_FOUND,
# PROGRESS, SELF_SKIPPED and DONE are printed by the CLI; the other codes come from
# tool.scan.ScanError. An unknown code is shown as NMAP_FAILED. {targets}, {address},
# {path}, {score}, {findings}, {count}, {hosts}, {step}, {percent} and {left} are
# filled in as plain text.
SCAN_MESSAGES: dict[str, dict[str, str]] = {
    "RUN_AS_ROOT": {
        "ro": "Nu porniți scanarea ca administrator (root). Porniți-o ca utilizator obișnuit: aplicația {name} cere parola doar pentru nmap.",
        "en": "Don't start the scan as administrator (root). Start it as a normal user: the {name} app asks for the password for nmap only.",
    },
    "START": {
        "ro": "Se verifică {targets}. nmap are nevoie de drepturi de administrator, așa că este posibil să vi se ceară parola.",
        "en": "Checking {targets}. nmap needs admin rights, so you may be asked for your password.",
    },
    "HOSTS_FOUND": {
        "ro": "Dispozitive găsite: {count} ({hosts}). Acum se verifică porturile lor, ceea ce durează de obicei câteva minute.",
        "en": "Devices found: {count} ({hosts}). Now checking their ports, which usually takes a few minutes.",
    },
    "PROGRESS": {
        "ro": "{step}: {percent}% gata, {left}.",
        "en": "{step}: {percent}% done, {left}.",
    },
    "SELF_SKIPPED": {
        "ro": "Acest calculator ({address}) nu este verificat: o scanare a lui însuși nu vede ce vede restul rețelei.",
        "en": "This computer ({address}) isn't checked: a scan of itself doesn't see what the rest of the network sees.",
    },
    "DONE": {
        "ro": "Scanare salvată: {path}. Scor: {score}/100. Probleme găsite: {findings}. Vedeți rezultatele cu comanda: bilet serve",
        "en": "Scan saved: {path}. Score: {score}/100. Findings: {findings}. See the results with the command: bilet serve",
    },
    "NMAP_NOT_FOUND": {
        "ro": "nmap nu este instalat. Instalați-l (de exemplu sudo apt install nmap sau brew install nmap) și încercați din nou.",
        "en": "nmap isn't installed. Install it (for example sudo apt install nmap or brew install nmap) and try again.",
    },
    "NMAP_DATA_NOT_FOUND": {
        "ro": "Aplicația {name} nu găsește lista de porturi a lui nmap (nmap-services). Setați TOOL_NMAP_SERVICES cu calea către fișier.",
        "en": "The {name} app can't find nmap's port list (nmap-services). Set TOOL_NMAP_SERVICES to the file's path.",
    },
    "NMAP_FAILED": {
        "ro": "Scanarea nu a reușit. Verificați parola de administrator și că sunteți conectat la rețeaua dumneavoastră, apoi încercați din nou.",
        "en": "The scan didn't work. Check the admin password and that you're on your own network, then try again.",
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

# Progress steps of `tool scan` (#107), keyed by the STEP_* codes in tool.scan. They fill
# {step} in SCAN_MESSAGES["PROGRESS"].
SCAN_STEPS: dict[str, dict[str, str]] = {
    "DEVICES": {"ro": "Se caută dispozitive", "en": "Looking for devices"},
    "TCP": {"ro": "Se verifică porturile (TCP)", "en": "Checking ports (TCP)"},
    "UDP": {"ro": "Se verifică porturile (UDP)", "en": "Checking ports (UDP)"},
    "SERVICES": {"ro": "Se identifică serviciile", "en": "Identifying services"},
    "TITLES": {"ro": "Se citesc titlurile paginilor web", "en": "Reading web page titles"},
    "OTHER": {"ro": "Scanarea continuă", "en": "The scan is still running"},
}

# Time left in a progress line (#107). {minutes} is a whole number of 2 or more, and
# Romanian says "20 de minute" from 20 on.
SCAN_TIME_LEFT: dict[str, dict[str, str]] = {
    "UNKNOWN": {"ro": "timpul rămas nu se știe încă", "en": "time left not known yet"},
    "UNDER_A_MINUTE": {"ro": "mai puțin de un minut rămas", "en": "less than a minute left"},
    "ONE_MINUTE": {"ro": "aproximativ un minut rămas", "en": "about 1 minute left"},
    "MINUTES": {"ro": "aproximativ {minutes} minute rămase", "en": "about {minutes} minutes left"},
    "MANY_MINUTES": {
        "ro": "aproximativ {minutes} de minute rămase",
        "en": "about {minutes} minutes left",
    },
}


def _fill_name(table: dict) -> None:
    """Put the product name into every `{name}` placeholder, in place.

    The name comes from tool.config.DISPLAY_NAME, so a rename stays a one-line change.
    It is filled in once, at import and before any caller adds its own values, so a
    target or path that contains "{name}" is never expanded.
    """
    for key, value in table.items():
        if isinstance(value, dict):
            _fill_name(value)
        elif isinstance(value, str):
            table[key] = value.replace("{name}", DISPLAY_NAME)


for _table in (REFUSALS, GENERIC_REFUSAL, SCAN_MESSAGES):
    _fill_name(_table)
