# ruff: noqa: E501
"""Fix steps for one catalog code on one type of device (#152, part 1 of #145).

The steps name the device and its IP address, say where to look and what the owner
will see when it's done. A code without a variant for a device type falls back to its
generic steps in texts.FINDINGS, so an unknown device type never breaks a page.

Placeholders: {ip} (the device's address) and {url} (its settings page in a browser).
They are filled from scan files in one pass and only ever shown as text. These texts
are local only: the AI layer uses the generic steps and never sees an IP address.

Existing Telnet, FTP and video-stream switch labels match the lab settings pages
in each language. HTTPS and software updates depend on the actual device; the
steps never assume the lab implements those controls.

Every variant has 1-5 steps, the same count in both languages (tests/test_content.py).
"""

FIX_PREFIXES = {
    "ro": "Acesta este pasul care rezolvă problema: ",
    "en": "This is the step that fixes it: ",
}

DEVICE_STEPS: dict[tuple[str, str], dict[str, list[str]]] = {
    ("TELNET_OPEN", "camera"): {
        "ro": [
            "Deschideți pagina de setări a camerei de la adresa {ip}: scrieți {url} în bara de adrese a browserului.",
            "Acesta este pasul care rezolvă problema: găsiți comutatorul „Telnet / acces la distanță” și treceți-l pe oprit. Comutatorul arată acum „oprit”.",
            "Dacă nu găsiți această opțiune, cereți ajutor persoanei care a configurat camera; o parolă nouă nu oprește serviciul Telnet.",
            "Schimbați parola camerei de la {ip} cu una lungă, pe care nu o folosiți în altă parte.",
        ],
        "en": [
            "Open the settings page of the camera at {ip}: type {url} in your browser's address bar.",
            "This is the step that fixes it: find the “Telnet / remote access” switch and turn it off. The switch now shows “off”.",
            "If you cannot find this option, ask whoever set up the camera for help; a new password does not turn Telnet off.",
            "Change the password of the camera at {ip} to a long one that you don't use anywhere else.",
        ],
    },
    ("HTTP_ADMIN_CLEARTEXT", "camera"): {
        "ro": [
            "Deschideți pagina de setări a camerei de la adresa {ip}: scrieți {url} în bara de adrese a browserului.",
            "Acesta este pasul care rezolvă problema: dacă există o opțiune HTTPS, activați-o și opriți accesul HTTP necriptat. Pagina trebuie să se deschidă doar cu https://.",
            "Dacă nu există HTTPS, cereți persoanei care a configurat camera să oprească serviciul web necriptat. Avertismentul rămâne cât timp pagina HTTP este accesibilă.",
            "Schimbați parola paginii de setări a camerei de la {ip}: nu păstrați parola din fabrică, folosiți una lungă și unică. Parola nouă ajută, dar singură nu rezolvă problema.",
        ],
        "en": [
            "Open the settings page of the camera at {ip}: type {url} in your browser's address bar.",
            "This is the step that fixes it: if an HTTPS option exists, enable it and turn off unencrypted HTTP access. The page must open only with https://.",
            "If HTTPS is unavailable, ask whoever set up the camera to turn off the unencrypted web service. The warning stays while the HTTP page is reachable.",
            "Change the settings password of the camera at {ip}: don't keep the factory password, use a long, unique one. A new password helps, but on its own it doesn't fix this.",
        ],
    },
    ("CAMERA_STREAM_EXPOSED", "camera"): {
        "ro": [
            "Deschideți pagina de setări a camerei de la adresa {ip}: scrieți {url} în bara de adrese a browserului.",
            "Acesta este pasul care rezolvă problema: dacă urmăriți camera doar din aplicația ei, opriți transmisia video (numită adesea RTSP sau ONVIF). Opțiunea arată acum „oprit”.",
            "Schimbați parola camerei de la {ip} cu una lungă, pe care nu o folosiți în altă parte.",
            "Instalați actualizările oferite de producătorul camerei, dacă există; denumirea opțiunii diferă după model.",
        ],
        "en": [
            "Open the settings page of the camera at {ip}: type {url} in your browser's address bar.",
            "This is the step that fixes it: if you only watch the camera through its own app, turn off the video stream (often called RTSP or ONVIF). The option now shows “off”.",
            "Change the password of the camera at {ip} to a long one that you don't use anywhere else.",
            "Install any update offered by the camera manufacturer; the option name depends on the model.",
        ],
    },
    ("FTP_CLEARTEXT", "camera"): {
        "ro": [
            "Deschideți pagina de setări a camerei de la adresa {ip}: scrieți {url} în bara de adrese a browserului.",
            "Acesta este pasul care rezolvă problema: găsiți comutatorul „FTP / partajare a fișierelor” și opriți-l. Comutatorul arată acum „oprit”.",
            "Dacă aveți nevoie să transferați înregistrări, cereți persoanei care a configurat camera o variantă criptată. O parolă nouă nu criptează FTP.",
        ],
        "en": [
            "Open the settings page of the camera at {ip}: type {url} in your browser's address bar.",
            "This is the step that fixes it: find the “FTP / file-sharing” switch and turn it off. The switch now shows “off”.",
            "If you need to transfer recordings, ask whoever set up the camera for an encrypted option. A new password does not encrypt FTP.",
        ],
    },
    ("OUTDATED_SERVICE", "camera"): {
        "ro": [
            "Verificați programul și versiunea veche indicate pentru camera de la adresa {ip}.",
            "Acesta este pasul care rezolvă problema: actualizați programul vechi sau opriți-l.",
            "Avertismentul rămâne dacă doar schimbați parola. El dispare când versiunea veche nu mai este accesibilă. Dacă pagina camerei nu are o opțiune de actualizare, cereți ajutor persoanei care a configurat camera.",
        ],
        "en": [
            "Check the old program and version reported for the camera at {ip}.",
            "This is the step that fixes it: update the old program or turn it off.",
            "Changing only the password leaves this warning in place. It clears when the old version is no longer reachable. If the camera's page has no update option, ask whoever set up the camera for help.",
        ],
    },
    # Router: no lab switch names here, because a real router's menus differ by model.
    # The steps say what to look for, never a menu path (MASTERPLAN §5.1).
    ("TELNET_OPEN", "router"): {
        "ro": [
            "Deschideți pagina de setări a routerului de la adresa {ip}: scrieți {url} în bara de adrese a browserului. Adresa și parola sunt adesea pe o etichetă lipită pe router.",
            "Acesta este pasul care rezolvă problema: găsiți opțiunea Telnet sau „acces de la distanță” și dezactivați-o.",
            "Dacă nu există această opțiune, instalați actualizarea de software oferită pentru router.",
            "Schimbați parola routerului de la {ip} cu una lungă, pe care nu o folosiți în altă parte.",
        ],
        "en": [
            "Open the settings page of the router at {ip}: type {url} in your browser's address bar. The address and password are often on a sticker on the router.",
            "This is the step that fixes it: find the Telnet or “remote access” option and turn it off.",
            "If there is no such option, install the software update offered for the router.",
            "Change the password of the router at {ip} to a long one that you don't use anywhere else.",
        ],
    },
    ("HTTP_ADMIN_CLEARTEXT", "router"): {
        "ro": [
            "Deschideți pagina de setări a routerului de la adresa {ip}: scrieți {url} în bara de adrese a browserului. Adresa și parola sunt adesea pe o etichetă lipită pe router.",
            "Acesta este pasul care rezolvă problema: activați HTTPS, dacă există această opțiune, și opriți accesul HTTP necriptat la setări. Pagina trebuie să se deschidă doar cu https://.",
            "Schimbați parola paginii de setări a routerului de la {ip}: nu păstrați parola din fabrică, folosiți una lungă și unică.",
            "Dacă routerul are o opțiune de administrare de la distanță prin internet, dezactivați-o.",
        ],
        "en": [
            "Open the settings page of the router at {ip}: type {url} in your browser's address bar. The address and password are often on a sticker on the router.",
            "This is the step that fixes it: enable HTTPS if that option exists, and turn off unencrypted HTTP access to settings. The page must open only with https://.",
            "Change the settings password of the router at {ip}: don't keep the factory password, use a long, unique one.",
            "If the router has an option for remote management over the internet, turn it off.",
        ],
    },
    ("UPNP_EXPOSED", "router"): {
        "ro": [
            "Deschideți pagina de setări a routerului de la adresa {ip}: scrieți {url} în bara de adrese a browserului. Adresa și parola sunt adesea pe o etichetă lipită pe router.",
            "Acesta este pasul care rezolvă problema: găsiți opțiunea UPnP și dezactivați-o.",
            "Dacă un joc sau un apel video nu mai funcționează după aceea, întrebați persoana care v-a configurat rețeaua înainte să reactivați UPnP pe routerul de la {ip}.",
        ],
        "en": [
            "Open the settings page of the router at {ip}: type {url} in your browser's address bar. The address and password are often on a sticker on the router.",
            "This is the step that fixes it: find the UPnP option and turn it off.",
            "If a game or a video call stops working afterwards, ask whoever set up your network before you turn UPnP back on for the router at {ip}.",
        ],
    },
    # Server and network storage box: use existing FTP labels, without assuming
    # a software-update switch exists on the simulated settings page.
    ("FTP_CLEARTEXT", "server"): {
        "ro": [
            "Deschideți pagina de setări a serverului de la adresa {ip}: scrieți {url} în bara de adrese a browserului.",
            "Acesta este pasul care rezolvă problema: găsiți comutatorul „FTP / partajare a fișierelor” și treceți-l pe oprit. Comutatorul arată acum „oprit”.",
            "Actualizarea de software nu oprește FTP: doar comutatorul face asta.",
            "Dacă aveți nevoie să partajați fișiere cu serverul de la {ip}, alegeți o variantă criptată (numită adesea SFTP).",
        ],
        "en": [
            "Open the settings page of the server at {ip}: type {url} in your browser's address bar.",
            "This is the step that fixes it: find the “FTP / file-sharing” switch and turn it off. The switch now shows “off”.",
            "A software update doesn't turn FTP off: only the switch does.",
            "If you need to share files with the server at {ip}, choose an encrypted option (often called SFTP).",
        ],
    },
    ("OUTDATED_SERVICE", "server"): {
        "ro": [
            "Deschideți pagina de setări a serverului de la adresa {ip}: scrieți {url} în bara de adrese a browserului.",
            "Acesta este pasul care rezolvă problema: instalați actualizarea oferită de producător pentru programul vechi sau opriți acel program. Avertismentul dispare când versiunea veche nu mai este accesibilă.",
            "Dacă nu există nicio actualizare, opriți programul vechi sau nu mai folosiți serverul de la {ip}.",
        ],
        "en": [
            "Open the settings page of the server at {ip}: type {url} in your browser's address bar.",
            "This is the step that fixes it: install the manufacturer’s update for the old program or turn that program off. The warning clears when the old version is no longer reachable.",
            "If there is no update, turn off the old program or stop using the server at {ip}.",
        ],
    },
    ("DB_EXPOSED", "server"): {
        "ro": [
            "Aflați ce program de pe serverul de la adresa {ip} folosește baza de date (de obicei un program instalat de un tehnician).",
            "Acesta este pasul care rezolvă problema: în setările acelui program, permiteți conexiuni la baza de date doar de pe serverul de la {ip} însuși.",
            "Setați o parolă puternică pentru baza de date.",
            "Dacă nu știți la ce folosește baza de date, întrebați persoana care a configurat serverul de la {ip}.",
        ],
        "en": [
            "Find out which program on the server at {ip} uses the database (often a program installed by a technician).",
            "This is the step that fixes it: in that program's settings, allow database connections only from the server at {ip} itself.",
            "Set a strong password for the database.",
            "If you don't know what the database is for, ask whoever set up the server at {ip}.",
        ],
    },
    ("SMB_EXPOSED", "server"): {
        "ro": [
            "Deschideți pagina de setări a serverului de la adresa {ip}: scrieți {url} în bara de adrese a browserului, apoi căutați „partajare”.",
            "Opriți partajarea pentru orice folder care nu trebuie partajat.",
            "Acesta este pasul care rezolvă problema: dacă nimic nu mai trebuie partajat, opriți complet partajarea de fișiere Windows (SMB) pe serverul de la {ip}.",
            "Dacă păstrați partajarea, asigurați-vă că fiecare folder cere o parolă puternică.",
        ],
        "en": [
            "Open the settings page of the server at {ip}: type {url} in your browser's address bar, then look for “sharing”.",
            "Stop sharing any folder that doesn't need to be shared.",
            "This is the step that fixes it: if nothing needs to be shared any more, turn Windows file sharing (SMB) off completely on the server at {ip}.",
            "If you keep sharing on, make sure every shared folder asks for a strong password.",
        ],
    },
    ("FTP_CLEARTEXT", "nas"): {
        "ro": [
            "Deschideți pagina de setări a dispozitivului de stocare de la adresa {ip}: scrieți {url} în bara de adrese a browserului.",
            "Acesta este pasul care rezolvă problema: găsiți opțiunea FTP sau de partajare a fișierelor și dezactivați FTP.",
            "Dacă aveți nevoie să partajați fișiere cu dispozitivul de stocare de la {ip}, alegeți o variantă criptată (numită adesea SFTP sau FTPS).",
        ],
        "en": [
            "Open the settings page of the storage box at {ip}: type {url} in your browser's address bar.",
            "This is the step that fixes it: find the FTP or file-sharing option and turn FTP off.",
            "If you need to share files with the storage box at {ip}, choose an encrypted option instead (often called SFTP or FTPS).",
        ],
    },
    ("SMB_EXPOSED", "nas"): {
        "ro": [
            "Deschideți pagina de setări a dispozitivului de stocare de la adresa {ip}: scrieți {url} în bara de adrese a browserului, apoi căutați „partajare”.",
            "Opriți partajarea pentru orice folder care nu trebuie partajat.",
            "Acesta este pasul care rezolvă problema: dacă nu mai aveți nevoie de partajare, opriți complet partajarea de fișiere Windows (SMB) pe dispozitivul de stocare de la {ip}. Dacă o păstrați accesibilă în rețea, avertismentul rămâne.",
            "Asigurați-vă că fiecare folder partajat cere o parolă puternică și că nu există acces pentru „guest” (oaspete).",
            "Instalați toate actualizările oferite pentru dispozitivul de stocare de la {ip}.",
        ],
        "en": [
            "Open the settings page of the storage box at {ip}: type {url} in your browser's address bar, then look for “sharing”.",
            "Stop sharing any folder that doesn't need to be shared.",
            "This is the step that fixes it: if you no longer need sharing, turn Windows file sharing (SMB) off completely on the storage box at {ip}. If you keep it reachable on the network, the warning stays.",
            "Make sure every shared folder asks for a strong password and that there is no “guest” access.",
            "Install all updates offered for the storage box at {ip}.",
        ],
    },
    # Smart-home hub: it may have only an app, so the steps offer both.
    ("MQTT_EXPOSED", "iot_hub"): {
        "ro": [
            "Deschideți aplicația hub-ului de la adresa {ip} sau pagina lui de setări: scrieți {url} în bara de adrese a browserului.",
            "Acesta este pasul care rezolvă problema: dacă nimic din casă nu folosește MQTT, dezactivați-l.",
            "Dacă folosiți MQTT, activați opțiunea care cere nume de utilizator și parolă. Mesajele sunt atunci protejate, dar avertismentul rămâne, pentru că serviciul poate fi încă accesat din rețea.",
            "Instalați orice actualizare de software oferită pentru hub-ul de la {ip}.",
        ],
        "en": [
            "Open the app of the hub at {ip}, or its settings page: type {url} in your browser's address bar.",
            "This is the step that fixes it: if nothing in your home uses MQTT, turn it off.",
            "If you do use MQTT, turn on the option that asks for a username and password. The messages are then protected, but the warning stays, because the service can still be reached on your network.",
            "Install any software update offered for the hub at {ip}.",
        ],
    },
    ("UPNP_EXPOSED", "iot_hub"): {
        "ro": [
            "Deschideți aplicația hub-ului de la adresa {ip} sau pagina lui de setări: scrieți {url} în bara de adrese a browserului.",
            "Acesta este pasul care rezolvă problema: găsiți opțiunea UPnP (uneori numită „descoperire în rețea”) și dezactivați-o.",
            "Dacă aplicația nu mai găsește hub-ul de la {ip} după aceea, întrebați persoana care l-a configurat înainte să reactivați opțiunea.",
        ],
        "en": [
            "Open the app of the hub at {ip}, or its settings page: type {url} in your browser's address bar.",
            "This is the step that fixes it: find the UPnP option (sometimes called “network discovery”) and turn it off.",
            "If the app can't find the hub at {ip} afterwards, ask whoever set it up before you turn the option back on.",
        ],
    },
    ("TELNET_OPEN", "iot_hub"): {
        "ro": [
            "Deschideți aplicația hub-ului de la adresa {ip} sau pagina lui de setări: scrieți {url} în bara de adrese a browserului.",
            "Acesta este pasul care rezolvă problema: găsiți opțiunea Telnet sau „acces de la distanță” și dezactivați-o.",
            "Dacă nu există această opțiune, instalați actualizarea de software oferită pentru hub-ul de la {ip}.",
        ],
        "en": [
            "Open the app of the hub at {ip}, or its settings page: type {url} in your browser's address bar.",
            "This is the step that fixes it: find the Telnet or “remote access” option and turn it off.",
            "If there is no such option, install the software update offered for the hub at {ip}.",
        ],
    },
}
