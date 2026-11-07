# ruff: noqa: E501
"""Fix steps for one catalog code on one type of device (#152, part 1 of #145).

The steps name the device and its IP address, say where to look and what the owner
will see when it's done. A code without a variant for a device type falls back to its
generic steps in texts.FINDINGS, so an unknown device type never breaks a page.

Placeholders: {ip} (the device's address) and {url} (its settings page in a browser).
They are filled from scan files in one pass and only ever shown as text. These texts
are local only: the AI layer uses the generic steps and never sees an IP address.

The switch names match the lab's fake settings pages exactly (#144): "Telnet / remote
access", "FTP / file sharing", "HTTPS / secure connection" and "Software update". If a
name changes here, #144's switch label changes too.

Every variant has 1-5 steps, the same count in both languages (tests/test_content.py).
"""

DEVICE_STEPS: dict[tuple[str, str], dict[str, list[str]]] = {
    ("TELNET_OPEN", "camera"): {
        "ro": [
            "Deschideți pagina de setări a camerei de la adresa {ip}: scrieți {url} în bara de adrese a browserului.",
            "Găsiți comutatorul „Telnet / remote access” și treceți-l pe oprit. Comutatorul arată acum „oprit”.",
            "Dacă nu există acest comutator, deschideți „Software update” și instalați actualizarea oferită pentru cameră.",
            "Schimbați parola camerei de la {ip} cu una lungă, pe care nu o folosiți în altă parte.",
        ],
        "en": [
            "Open the settings page of the camera at {ip}: type {url} in your browser's address bar.",
            "Find the “Telnet / remote access” switch and turn it off. The switch now shows “off”.",
            "If there is no such switch, open “Software update” and install the update offered for the camera.",
            "Change the password of the camera at {ip} to a long one that you don't use anywhere else.",
        ],
    },
    ("HTTP_ADMIN_CLEARTEXT", "camera"): {
        "ro": [
            "Deschideți pagina de setări a camerei de la adresa {ip}: scrieți {url} în bara de adrese a browserului.",
            "Acesta este pasul care rezolvă problema: găsiți comutatorul „HTTPS / secure connection” și porniți-l. De acum adresa paginii începe cu https://.",
            "Schimbați parola paginii de setări a camerei de la {ip}: nu păstrați parola din fabrică, folosiți una lungă și unică. Parola nouă ajută, dar singură nu rezolvă problema.",
        ],
        "en": [
            "Open the settings page of the camera at {ip}: type {url} in your browser's address bar.",
            "This is the step that fixes it: find the “HTTPS / secure connection” switch and turn it on. From now on the page address starts with https://.",
            "Change the settings password of the camera at {ip}: don't keep the factory password, use a long, unique one. A new password helps, but on its own it doesn't fix this.",
        ],
    },
    ("CAMERA_STREAM_EXPOSED", "camera"): {
        "ro": [
            "Deschideți pagina de setări a camerei de la adresa {ip}: scrieți {url} în bara de adrese a browserului.",
            "Dacă urmăriți camera doar din aplicația ei, opriți transmisia video (numită adesea RTSP sau ONVIF). Opțiunea arată acum „oprit”.",
            "Schimbați parola camerei de la {ip} cu una lungă, pe care nu o folosiți în altă parte.",
            "Deschideți „Software update” și instalați actualizarea oferită pentru cameră, dacă există una.",
        ],
        "en": [
            "Open the settings page of the camera at {ip}: type {url} in your browser's address bar.",
            "If you only watch the camera through its own app, turn off the video stream (often called RTSP or ONVIF). The option now shows “off”.",
            "Change the password of the camera at {ip} to a long one that you don't use anywhere else.",
            "Open “Software update” and install the update offered for the camera, if there is one.",
        ],
    },
}
