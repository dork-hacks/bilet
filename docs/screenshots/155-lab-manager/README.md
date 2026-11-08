# Lab manager: assets for the slides

Screenshots of the **real** lab manager and bilet, captured on 8 Nov 2026 on `RSH-dork_unit`.
The bilet pages (09–12) are rendered from the real lab captures `L1`/`L2`. `12` was retaken after #287,
so its Romanian matches `main`. The others are in English, so #287 doesn't change them.
The access code doesn't appear anywhere in this folder. Keep it that way: anyone on the
hotspot, jury included, can reach the sign-in page.

All PNGs are 2x (retina), so they stay sharp on a 16:9 slide.

## Images

| File | What it shows | Suggested slide |
|---|---|---|
| `00-signin-on-router.png` | The router's sign-in page at 192.168.50.1:8090 (empty field) | Safety: the page needs a code |
| `01-overview-light.png` | Default lab: camera 60 pts, hub 15, server 0, **expected score 25** | "This is our house in a box" |
| `02-overview-dark.png` | Same, dark mode | Optional |
| `03-phone-light.png` | Same page on a phone | "Works from any phone on the hotspot" |
| `04-all-services-open.png` | Camera with every service shown (Other services expanded) | What a Pi can play |
| `05-after-two-fixes.png` | Telnet and the admin page switched off: **55** | Demo step 1 |
| `06-camera-all-fixed.png` | FTP off too, camera "All fixed": **85** | Demo step 2 |
| `07-preset-choices.png` | The "Plays" list: camera, server, hub, printer, smart-light, nas, custom | Any Pi can be any device |
| `08-pi4-now-a-printer.png` | pi4 switched to a printer: 30 points on, **70** | Switching roles in one click |
| `09-bilet-home-before-25.png` / `09a-…-first-screen.png` | bilet's home on the default lab: 25, "Most dangerous device: Camera" | Before |
| `10-bilet-home-after-55.png` / `10a-…-first-screen.png` | bilet after the two fixes: 55 | After |
| `11-bilet-history-25-to-55.png` / `11a-…-first-screen.png` | History: "went up from 25 to 55", 2 problems fixed | Proof that fixing works |
| `12-bilet-home-before-25-ro-phone.png` / `12a-…-first-screen.png` | bilet in Romanian on a phone, with the polite "dumneavoastră" wording from #287 | Built for parents and grandparents |
| `20-architecture.svg` / `.png` | How a click reaches a Pi, and the safety on every hop | Architecture |

The `a` files are the first screen only (1440×900), so they fit a slide. The others are full
pages for scrolling or cropping.

## The story in one line

**The lab manager is the "remote control" for our fake house. bilet is the tool that has to
find out on its own what we changed.** The two never talk to each other: the manager only
predicts the score, and bilet's own scan is the real answer.

## Talking points

**What it is**
- One web page on the Pi 5 router that controls all three lab Pis.
- Each Pi can play any of 7 devices: camera, hub, server, printer, smart light, NAS or custom.
- 11 weak services, each with its catalog code and points, and an on/off switch for each one.
  Also "Fix everything" and "Back to the preset" per Pi.
- It shows **what the lab should score** (100 minus the points switched on), so we know the
  right answer before bilet scans. For example, the default lab predicts 25 and bilet's live
  scan measured 25.
- The Pi's LED shows the state, so the jury sees the fix on the hardware too: blinking red
  means weak, steady green means fixed.

**Why we built it**
- To show "before → fix → after" live in seconds, without SSH or typing commands.
- To test bilet against many device mixes, not only the three we planned.
- To let anyone on the team run the lab from a phone.

**Safety (the 10% criterion)**
- **Simulate, do not expose:** the services are fake banners with no real data, shells or
  passwords.
- **Least privilege:** the manager runs as an unprivileged user. It reaches each Pi over SSH
  with a key that can't open a shell, a PTY or forwarding. The key can only pass one line to
  a helper.
- **Only 4 requests ever reach a Pi:** `status`, `fix SERVICE`, `break SERVICE`,
  `preset NAME`. They're checked on the router and again on the Pi.
- **Web hardening:** an access code, 30-minute HttpOnly/SameSite cookies, a 1 s delay after a
  wrong code, CSRF tokens on every form, and a refusal for foreign `Host` headers (DNS
  rebinding).
- **It doesn't spoil the score:** a scan sees the router as SSH plus a page titled
  "Lab manager". That title has no admin word, so the router still adds 0 points.
- **Privacy:** Pis are found by MAC in the router's DHCP leases, and the MACs are never shown
  on the page.
- **No extra installs on the router:** only Python's standard library, run under OpenWrt's
  procd.

**Demo flow (matches the screenshots)**
1. Lab manager shows 25 (01) → bilet's home shows 25 and "Most dangerous device: Camera" (09a).
2. Switch off Telnet and the admin page on the camera (05: 55) → "Check again" in bilet → 55 (10a).
3. bilet's history: "went up from 25 to 55" (11a).
4. Optional: switch off FTP (06: 85), or turn pi4 into a printer (08) and bilet spots it.

## Numbers you can quote

| | |
|---|---|
| Lab devices | 3 Pi 4 targets + the Pi 5 router |
| Device presets | 7 |
| Weak services | 11 (telnet, admin page, RTSP, FTP, Redis, Samba, MQTT, UPnP, SNMP, JetDirect, hidden identity) |
| Default lab | camera 60 + hub 15 + server 0 → score **25** |
| Whole-hotspot live scan | under 270 s with 5 devices on the hotspot (limit: 300 s, NFR-07) |
| Requests a Pi accepts | 4 |
| Status refresh | every 10 s, only while someone has the page open |
| Manager code | one stdlib Python file, ~870 lines, with offline tests |

## Don't show

- The access code (`LAB-XXXX-XXXX` is the format only).
- Any MAC address, or `pis.conf` from the router.
- Real hostnames other than the role names (pi2, pi3, pi4).
