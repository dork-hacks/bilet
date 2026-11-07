#!/usr/bin/env bash
# Make a Pi OS card (flashed with flash_pi.sh) join a Wi-Fi network on first boot.
# Writes cloud-init's network-config on the boot partition and sets the Wi-Fi country.
# No sudo needed: the boot partition is FAT and gets mounted as your user.
# Only works before the card's first boot; after that, use nmcli on the Pi.
#
# Usage: lab/pi_wifi.sh <device> <ssid> [--country RO]
#   lab/pi_wifi.sh /dev/sdb RSH-dork_unit
# The Wi-Fi password is asked for (it is never passed on the command line).
set -euo pipefail
source "$(dirname "$0")/_card.sh"

[[ $# -ge 2 ]] || { sed -n '2,10p' "$0"; exit 1; }
DEV=$1; SSID=$2; shift 2; COUNTRY=RO
while [[ $# -gt 0 ]]; do
  case $1 in
    --country) COUNTRY=$2; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ $COUNTRY =~ ^[A-Z]{2}$ ]] || die "country must be a 2-letter code like RO"
[[ ${#SSID} -ge 1 && ${#SSID} -le 32 ]] || die "SSID must be 1-32 characters"
check_card "$DEV"

BOOT=$(part "$DEV" 1)
[[ $(lsblk -no LABEL "$BOOT") == bootfs ]] || die "$BOOT is not a Pi OS boot partition"
MNT=$(lsblk -no MOUNTPOINTS "$BOOT" | head -n1)
if [[ -z $MNT ]]; then
  MNT=$(udisksctl mount -b "$BOOT" | sed 's/.* at //')
fi
[[ -f $MNT/user-data ]] || die "no user-data on $BOOT; flash it with lab/flash_pi.sh first"
grep -qw resize "$MNT/cmdline.txt" || echo "WARNING: this card has already booted once; network-config is only read on first boot." >&2
HOST=$(sed -n 's/^hostname: *//p' "$MNT/user-data")

read -rsp "Wi-Fi password for '$SSID' (empty if open): " PASS </dev/tty; echo
[[ -z $PASS || ( ${#PASS} -ge 8 && ${#PASS} -le 63 ) ]] || die "WPA passwords are 8-63 characters"

# network-config (netplan v2, rendered by NetworkManager). JSON strings are valid YAML.
WIFI_SSID=$SSID WIFI_PASS=$PASS WIFI_COUNTRY=$COUNTRY python3 -I - "$MNT/network-config" <<'PY'
import json, os, sys
q = json.dumps
ssid, pw, cc = os.environ["WIFI_SSID"], os.environ["WIFI_PASS"], os.environ["WIFI_COUNTRY"]
ap = f"        {q(ssid)}:\n" + (f"          password: {q(pw)}\n" if pw else "          {}\n")
with open(sys.argv[1], "w") as f:
    f.write(f"""# Written by lab/pi_wifi.sh; applied by cloud-init on first boot only.
network:
  version: 2
  wifis:
    renderer: NetworkManager
    wlan0:
      dhcp4: true
      optional: true
      regulatory-domain: {q(cc)}
      access-points:
{ap}""")
PY
unset PASS

# Wi-Fi stays blocked (rfkill) until a country is set; set it on the kernel command line too.
CMD=$(head -n1 "$MNT/cmdline.txt" | sed -E 's/ ?cfg80211\.ieee80211_regdom=[A-Z]+//')
printf '%s cfg80211.ieee80211_regdom=%s\n' "$CMD" "$COUNTRY" > "$MNT/cmdline.txt"

sync
udisksctl unmount -b "$BOOT" >/dev/null && echo "Unmounted $BOOT; safe to remove the card."
echo "DONE: ${HOST:-the Pi} will join '$SSID' on first boot (country $COUNTRY)."
