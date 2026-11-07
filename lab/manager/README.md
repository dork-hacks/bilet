# Lab manager (#155)

One page on the Pi 5 (the hotspot router) that controls what every lab Pi plays:

- **Presets:** each Pi can play any device: `camera`, `server`, `hub` (the roles in
  `../services.tsv`), or `printer`, `smart-light`, `nas` and `custom` (`../presets.tsv`).
  Choosing one turns its services on and everything else off.
- **Custom devices:** any service can be turned on on any Pi. Two services on the same port
  are refused.
- **Fix / break buttons** for every service on every Pi, plus "Fix everything" and "Back to
  the preset" per Pi.
- **What the lab should score:** 100 minus the points of everything that's switched on,
  from `services.tsv`. The tool's own scan is still the real answer.

## Safety

- It listens on **127.0.0.1:8090 only**, so it never appears in a scan, and the router still
  adds 0 points (MASTERPLAN §4.2). Requests whose `Host` isn't the loopback are refused, and
  every button carries a CSRF token.
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

On the router (`ssh root@<pi5>`), once, over its uplink:

```bash
opkg update && opkg install python3-light
```

From the laptop, copy the lab folder over (`-O`: dropbear has no sftp):

```bash
scp -O -r lab root@<pi5>:/tmp/lab
```

On the router:

```bash
sh /tmp/lab/manager/setup_openwrt.sh     # installs, starts, prints the public key
vi /etc/lab-manager/pis.conf              # one line per Pi: NAME IP (see pis.conf.example)
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

`pis.conf` stays on the router: it isn't committed (MASTERPLAN §3.5).

**On a regular Linux machine with systemd** (not our router), `setup_manager.sh` does the
same with `lab-manager.service` and OpenSSH.

## Not verified yet

Offline tests only (`lab/tests/test_manager.py`, `test_labctl_presets.py`). It still needs a
run on `RSH-dork_unit`: switch pi3 from `hub` to `camera` and back, fix and break from the
page, then rescan.
