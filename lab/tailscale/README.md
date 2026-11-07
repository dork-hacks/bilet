# Reaching the lab from home (#199)

The team is no longer in one room, and only Sc1pex has the lab. One lab Pi runs Tailscale as
a **subnet router** for the hotspot subnet, so a teammate's laptop on our tailnet can reach every
device on `RSH-dork_unit` as if it were on the hotspot: the Pis, the lab manager on the Pi 5 and
the camera's settings page. The Pi 5 router doesn't change.

```
teammate laptop ──tailnet──► camera Pi (subnet router) ──hotspot──► other Pis, Pi 5
   100.x.y.z                    SNAT: teammates appear as the camera Pi's address
```

## What it can and can't reach

- Only the hotspot subnet this Pi is on, and only if it is private (RFC 1918) and a /24 or
  smaller. The script detects it and refuses anything else, including CGNAT 100.64.0.0/10.
- Never an exit node: nobody's internet goes through the lab, and the lab can't reach the
  teammates' machines (the Pis can't start connections into the tailnet).
- No secret is stored: login is through the URL `tailscale up` prints.
- Tailscale adds no TCP port to the Pi's LAN address, and its UDP port (41641) isn't one the
  scan probes, so the lab still scores 25. Check that on the first scan after the setup.

## Setup (Sc1pex, once, on the camera Pi)

Use the camera Pi (pi2): its default services are all TCP. A teammate who connects to the
subnet router's own address comes from a 100.x address, and the fake SSDP responder only
answers private peers, so on the hub that one service would look different from home.

```bash
lab/tailscale/setup_pi.sh --print-only     # which subnet it would advertise, changes nothing
sudo lab/tailscale/setup_pi.sh             # installs Tailscale if needed, prints a login URL
```

Then, in the [admin console](https://login.tailscale.com/admin/machines) (the script prints
these steps with the real subnet):

1. **`bilet-lab` → Edit route settings → approve the subnet.**
2. **`bilet-lab` → Disable key expiry**, so the route doesn't vanish mid-event.
3. **Invite each teammate as a user** (Settings → Users → Invite). Sharing the machine with
   them is not enough: a shared node doesn't share its subnet routes.
4. Optional, so remote scans see hostnames: **DNS → Add nameserver → Custom**, the Pi 5's
   hotspot address, **Restrict to domain** the reverse zone the script prints
   (`50.168.192.in-addr.arpa` for `192.168.50.0/24`). See "Scanning from home" for why.

To stop it: `sudo lab/tailscale/setup_pi.sh remove` (logs out, stops Tailscale, forwarding off).
`sudo tailscale down` pauses it and `sudo tailscale up` brings it back.

## For teammates

1. Accept the invite, install Tailscale and log in with that account.
2. Accept the lab route:
   - Linux: `sudo tailscale set --accept-routes`
   - macOS and Windows: in the Tailscale menu, turn on **Use Tailscale subnets**.
3. Check: `ping 192.168.50.1` (the Pi 5; use the real hotspot subnet if it differs).

If your home network uses the same subnet as the hotspot, the two collide and you may reach
the wrong devices. Check `ip -4 addr` / `ifconfig` first, and don't scan until that's sorted.

Then, from home:

- **Lab manager:** `http://<pi5>:8090/` with the access code, when it runs with `--hotspot`
  ([manager/README.md](../manager/README.md)).
- **Camera settings page:** `http://<camera-ip>/`, `admin` and the device ID from the label
  (ask Sc1pex).
- **SSH to a Pi:** key-only, so Sc1pex has to add your public key to that Pi first.

## Scanning from home

Humans only: agents still never scan (WORKFLOW.md). The guardrail already allows an explicitly
configured extra range, so no code changes:

```bash
TOOL_SCAN_ALLOWLIST=192.168.50.0/24 bilet scan 192.168.50.0/24 --confirm --scans-dir scans-remote
```

A scan from home is **not** the same as one on the hotspot:

- **No MAC addresses.** Over a routed link nmap never sees them, so there are no vendors, and
  history can't match devices to on-site scans. Keep remote scans in their own folder.
- **UNKNOWN_DEVICE** is "no vendor, no hostname", so without a vendor every device needs its
  hostname. Hostnames come from reverse DNS, which only the Pi 5 can answer: set up step 4
  above, and check with `dig -x <camera-ip>`. Without it, every device gets UNKNOWN_DEVICE.
- **The subnet router's own address** behaves slightly differently (see Setup).
- nmap's raw scans may not work on macOS over Tailscale's `utun` interface. Use Linux, or ask
  Sc1pex to scan.

So remote scans are for development. Captures for `tests/fixtures/lab/`, `lab/verify` (it
refuses targets outside the laptop's own network, on purpose), the Test Set run and the jury's
live checks stay on the scanner laptop **on the hotspot, with Tailscale off on that laptop**.

## Not verified yet

Offline tests only (`lab/tests/test_tailscale.py`). Still to do on the lab: run the setup on the
camera Pi, reach the Pi 5 and the hub from outside, and scan once on the hotspot to confirm the
camera Pi's findings didn't change.
