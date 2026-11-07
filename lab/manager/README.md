# Lab manager (#155)

One page on the Pi 5 (the hotspot router) that controls what every lab Pi plays:

- **Presets:** each Pi can play any device: `camera`, `server`, `hub` (the roles in
  `../services.tsv`), or `printer`, `smart-light`, `nas` and `custom` (`../presets.tsv`).
  Choosing one turns its services on and everything else off.
- **Custom devices:** any service can be turned on on any Pi. Two services on the same port
  are refused.
- **Fix / break buttons** for every service on every Pi, plus "Fix everything" and "Back to
  the preset" per Pi.
- **Fast page:** it remembers each Pi's last status and refreshes it every 10 s while
  someone has the page open (in the last 5 minutes), so the page loads at once. A switch
  shows its new state right away; the Pi confirms it in the background.
- **What the lab should score:** 100 minus the points of everything that's switched on,
  from `services.tsv`. The tool's own scan is still the real answer.

## Safety

- By default it listens on **127.0.0.1:8090 only**, so it never appears in a scan.
- With `--hotspot` it listens on the router's hotspot address instead (never `0.0.0.0`, which
  would include the uplink), and every page needs the **access code** printed by the setup.
  Anyone on `RSH-dork_unit` can reach the sign-in page, jury included, so keep the code off
  slides and screenshots. Sessions are HttpOnly, SameSite=Strict cookies that last 30 minutes;
  a wrong code waits 1 s.
- A scan then shows `http` on 8090 titled "Lab manager". It has no admin word, so there's no
  HTTP_ADMIN_CLEARTEXT and the router still adds 0 points (MASTERPLAN §4.2). The sign-in page
  is served at `/` directly, not through a redirect, so `http-title` sees that title.
- Requests whose `Host` isn't one of our own addresses are refused (DNS rebinding), and every
  form carries a CSRF token.
- It reaches each Pi as `labmgr` over SSH (already open: SSH_OPEN, 0 points) with its own
  key. On the Pi that key is `restrict`ed to `remote.py`, so it gets no shell, no PTY and no
  forwarding. `remote.py` hands one line to the lab-switch helper, which accepts only
  `status`, `fix SERVICE`, `break SERVICE` or `preset NAME` and runs `labctl` with a fixed
  argv. The manager checks the same grammar before it connects.
- On the router it runs as the unprivileged user `labmanager` (procd). Its key lives in
  `/etc/lab-manager/state` (mode 0700).

## Setup on the router (the Pi 5, OpenWrt)

The router runs OpenWrt, so the manager uses its own pieces: an `/etc/init.d` script
(procd) instead of systemd, and dropbear's `dbclient` instead of OpenSSH. Only python3 has
to be added.

On the router (`ssh root@<pi5>`), once, over its uplink. OpenWrt 25.12 uses `apk`
(older releases: `opkg update && opkg install` with the same names). `python3-light` alone
lacks modules that `http.server` needs, so the four extra packages are required (about 10 MB
in total):

```bash
apk update && apk add python3-light python3-email python3-urllib python3-logging python3-codecs
```

From the laptop, copy the lab folder over (`-O`: dropbear has no sftp):

```bash
scp -O -r lab root@<pi5>:/tmp/lab
```

On the router:

```bash
sh /tmp/lab/manager/setup_openwrt.sh     # installs, starts, prints the public key
vi /etc/lab-manager/pis.conf              # one line per Pi: NAME MAC[,MAC] (see pis.conf.example)
/etc/init.d/lab-manager restart
```

It runs as the user `labmanager`. Its key and known hosts live in `/etc/lab-manager/state`
(0700), on flash, so they survive a reboot. `logread -e lab-manager` shows its log.

On each lab Pi, with the printed key saved as `lab-manager.pub`:

```bash
sudo lab/setup.sh camera --manager-key lab-manager.pub   # or hub, server
```

From the laptop:

```bash
ssh -L 8090:127.0.0.1:8090 root@<pi5>
```

Then open http://127.0.0.1:8090/.

To open it from any device on the hotspot instead (no tunnel), run the setup again with the
router's hotspot address. It prints the access code (kept in `/etc/lab-manager/state/access-code`):

```bash
sh /tmp/lab/manager/setup_openwrt.sh --hotspot 192.168.50.1
```

Then open http://192.168.50.1:8090/. Running the setup without `--hotspot` goes back to loopback.

`pis.conf` stays on the router: it isn't committed (MASTERPLAN §3.5).

**Addresses come from DHCP.** List each Pi by MAC, not IP: the manager looks up its current
address in the router's DHCP leases (`/tmp/dhcp.leases`) every 10 s while the page is in use,
and on **Find the Pis again**. So a Pi that gets a new address is found again without editing
anything. The hub needs both its MACs (its random one while UNKNOWN_DEVICE is on, its real one
when that is fixed); the newest lease wins. The MACs stay in `pis.conf` on the router and never
appear on the page. A Pi with a static lease can still be listed by IP.

SSH host keys are kept per Pi name (`state/hosts/NAME/`), not per IP, so a Pi with a new
address, or two Pis that swap addresses, still connect.

**On a regular Linux machine with systemd** (not our router), `setup_manager.sh` does the
same with `lab-manager.service` and OpenSSH.

## Not verified yet

Offline tests only (`lab/tests/test_manager.py`, `test_labctl_presets.py`). It still needs a
run on `RSH-dork_unit`: switch pi3 from `hub` to `camera` and back, fix and break from the
page, then rescan.
