#!/usr/bin/env bash
# Write a native NetworkManager Wi-Fi connection onto a Pi OS card (booted or not).
# More robust than cloud-init's network-config: NetworkManager reads it directly on every boot,
# retries forever until the network appears, and it can be edited later with nmcli.
# Also turns on persistent logs (Pi OS keeps them in RAM only), so a failed connection
# can be diagnosed afterwards with:  sudo journalctl -D <rootfs>/var/log/journal -u NetworkManager
#
# Also sets the Wi-Fi country: Pi OS keeps Wi-Fi blocked (rfkill) until one is set.
#
# Usage: sudo lab/pi_wifi_nm.sh <device> <ssid> [--country RO]
#   sudo lab/pi_wifi_nm.sh /dev/sdb RSH-dork_unit
# The password is taken from the card's existing cloud-init/netplan config for that SSID if
# there is one, otherwise you are asked for it.
set -euo pipefail
source "$(dirname "$0")/_card.sh"

[[ $EUID -eq 0 ]] || die "run with sudo"
[[ $# -ge 2 ]] || { sed -n '2,14p' "$0"; exit 1; }
DEV=$1; SSID=$2; shift 2; COUNTRY=RO
while [[ $# -gt 0 ]]; do
  case $1 in
    --country) COUNTRY=$2; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ $COUNTRY =~ ^[A-Z]{2}$ ]] || die "country must be a 2-letter code like RO"
[[ ${#SSID} -ge 1 && ${#SSID} -le 32 && $SSID != *$'\n'* ]] || die "bad SSID"
check_card "$DEV"

ROOT=$(part "$DEV" 2)
[[ $(lsblk -no LABEL "$ROOT") == rootfs && $(lsblk -no FSTYPE "$ROOT") == ext4 ]] || die "$ROOT is not a Pi OS root partition"
unmount_all "$DEV"
MNT=$(mktemp -d); trap 'umount "$MNT" 2>/dev/null; rmdir "$MNT" 2>/dev/null' EXIT
mount "$ROOT" "$MNT"
[[ -d $MNT/etc/NetworkManager/system-connections ]] || die "no NetworkManager on this card"
HOST=$(cat "$MNT/etc/hostname" 2>/dev/null || echo "the Pi")

# Password: reuse the one cloud-init/netplan already has for this SSID, else ask.
PASS=$(SSID=$SSID python3 -I - "$MNT"/etc/netplan/*.yaml 2>/dev/null <<'PY' || true
import os, sys, yaml
for path in sys.argv[1:]:
    try:
        wifis = (yaml.safe_load(open(path)) or {}).get("network", {}).get("wifis", {})
    except Exception:
        continue
    for iface in wifis.values():
        ap = (iface.get("access-points") or {}).get(os.environ["SSID"])
        if ap is not None:
            pw = ap.get("password") or (ap.get("auth") or {}).get("password") or ""
            print(pw, end="")
            sys.exit(0)
PY
)
if [[ -n $PASS ]]; then
  echo "Using the password already stored on the card for '$SSID'."
else
  read -rsp "Wi-Fi password for '$SSID': " PASS </dev/tty; echo
fi
[[ ${#PASS} -ge 8 && ${#PASS} -le 63 ]] || die "WPA passwords are 8-63 characters"

# GKeyFile escaping for values
esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/^ /\\s/'; }
NAME=$(printf '%s' "$SSID" | tr -c 'A-Za-z0-9_.-' '_')
CONN="$MNT/etc/NetworkManager/system-connections/$NAME.nmconnection"
umask 077
cat > "$CONN" <<EOF
[connection]
id=$(esc "$SSID")
uuid=$(cat /proc/sys/kernel/random/uuid)
type=wifi
interface-name=wlan0
autoconnect=true
autoconnect-priority=10
autoconnect-retries=0

[wifi]
mode=infrastructure
ssid=$(esc "$SSID")

[wifi-security]
key-mgmt=wpa-psk
psk=$(esc "$PASS")

[ipv4]
method=auto

[ipv6]
method=auto
addr-gen-mode=default
EOF
unset PASS
chown root:root "$CONN"; chmod 600 "$CONN"

# Drop the netplan copy of the same network so there is one profile to edit with nmcli.
for f in "$MNT"/etc/netplan/*.yaml; do
  [[ -f $f ]] && grep -qF "\"$SSID\"" "$f" && { mv "$f" "$f.disabled"; echo "Disabled $(basename "$f") (same network, now handled by NetworkManager)"; }
done

# Persistent logs: /etc overrides Pi OS's /usr/lib/.../40-rpi-volatile-storage.conf
install -d -m 755 "$MNT/etc/systemd/journald.conf.d"
printf '[Journal]\nStorage=persistent\nSystemMaxUse=50M\n' > "$MNT/etc/systemd/journald.conf.d/99-lab-persistent.conf"
install -d -m 2755 -g "$(stat -c %g "$MNT/var/log/journal" 2>/dev/null || echo 0)" "$MNT/var/log/journal"

# Wi-Fi country: unblock the saved rfkill state (as Raspberry Pi Imager does) ...
shopt -s nullglob
for f in "$MNT"/var/lib/systemd/rfkill/*:wlan; do echo 0 > "$f"; done
shopt -u nullglob
sync; umount "$MNT"

# ... and set the regulatory domain on the kernel command line (boot partition).
BOOT=$(part "$DEV" 1)
[[ $(lsblk -no LABEL "$BOOT") == bootfs ]] || die "$BOOT is not a Pi OS boot partition"
mount "$BOOT" "$MNT"
CMD=$(head -n1 "$MNT/cmdline.txt" | sed -E 's/ ?cfg80211\.ieee80211_regdom=[A-Z]+//')
printf '%s cfg80211.ieee80211_regdom=%s\n' "$CMD" "$COUNTRY" > "$MNT/cmdline.txt"
sync; umount "$MNT"
echo "DONE: $HOST will join '$SSID' on every boot (WPA2, country $COUNTRY). Safe to remove the card."
