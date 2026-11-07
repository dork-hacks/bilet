#!/usr/bin/env bash
# Put a lab role on a Pi OS card (flashed with flash_pi.sh, booted or not) from the laptop.
# Only the FAT boot partition is written, so no sudo is needed. On the Pi's next boot:
#   1. a one-shot hook (systemd.run=, the same mechanism Raspberry Pi Imager uses) copies the
#      lab files to /opt/lab-src, enables lab-install.service and removes itself;
#   2. after the Pi reboots and is online, lab-install.service runs `setup.sh <role>`, turns on
#      any extra services, then disables itself. The hub reboots once more for its new identity.
# Progress on the Pi: journalctl -u lab-install   (or /var/log/lab-install.log)
#
# Usage: lab/card_role.sh <device> camera|server|hub [options]
#   lab/card_role.sh /dev/sdb hub --on ssdp,jetdirect     # pi3
#   lab/card_role.sh /dev/sdb server                      # pi2
# Options:
#   --on SVC[,SVC]     also turn on these toggles of the role (see lab/services.tsv)
#   --with-packages    let setup.sh apt-install samba/snmpd (needs internet; hotspot data is limited)
# Tests only: lab/card_role.sh --to-dir DIR <role> [options] writes into a plain folder that stands
# in for the boot partition (no disk checks, no mount), see lab/tests/test_card_role.py.
set -euo pipefail
source "$(dirname "$0")/_card.sh"

[[ $# -ge 2 ]] || { sed -n '2,16p' "$0"; exit 1; }
TO_DIR=
if [[ $1 == --to-dir ]]; then
  [[ $# -ge 3 ]] || die "usage: $0 --to-dir DIR <role> [options]"
  TO_DIR=$2; shift
fi
DEV=$1; ROLE=$2; shift 2; ON=(); ARGS=
while [[ $# -gt 0 ]]; do
  case $1 in
    --on)            IFS=, read -ra extra <<<"$2"; ON+=("${extra[@]}"); shift 2 ;;
    --with-packages) ARGS=--with-packages; shift ;;
    *) die "unknown option $1" ;;
  esac
done
[[ $ROLE =~ ^(camera|server|hub)$ ]] || die "role must be camera, server or hub"

HERE=$(cd "$(dirname "$0")" && pwd)
for svc in "${ON[@]}"; do
  awk -F'\t' -v s="$svc" -v r="$ROLE" '!/^#/ && $1 == s && $2 == r { f = 1 } END { exit !f }' \
    "$HERE/services.tsv" || die "'$svc' is not a service of the $ROLE role (see lab/services.tsv)"
done
if [[ -n $TO_DIR ]]; then
  [[ -d $TO_DIR ]] || die "$TO_DIR is not a folder"
  BOOT=; MNT=$TO_DIR
else
  check_card "$DEV"
  BOOT=$(part "$DEV" 1)
  [[ $(lsblk -no LABEL "$BOOT") == bootfs ]] || die "$BOOT is not a Pi OS boot partition"
  MNT=$(lsblk -no MOUNTPOINTS "$BOOT" | head -n1)
  if [[ -z $MNT ]]; then
    MNT=$(udisksctl mount -b "$BOOT" | sed 's/.* at //')
  fi
fi
[[ -f $MNT/cmdline.txt && -w $MNT/cmdline.txt ]] || die "can't write $MNT/cmdline.txt"

# --- Payload: the lab files setup.sh installs, plus the role -------------------------
rm -rf "$MNT/lab"
mkdir -p "$MNT/lab/fakes" "$MNT/lab/systemd"
cp "$HERE/setup.sh" "$HERE/labctl" "$HERE/services.tsv" "$HERE/README.md" "$MNT/lab/"
cp "$HERE/fakes/fakesvc.py" "$MNT/lab/fakes/"
cp "$HERE"/systemd/*.service "$MNT/lab/systemd/"
printf '%s\n' "$ROLE" > "$MNT/lab/role"
printf '%s\n' "$ARGS" > "$MNT/lab/args"
printf '%s\n' "${ON[@]}" > "$MNT/lab/on"

cat > "$MNT/lab/install-role.sh" <<'EOF'
#!/bin/bash
# Run by lab-install.service once the Pi is online. Disables itself only on success,
# so a failed install (e.g. no internet for --with-packages) is retried on the next boot.
set -euo pipefail
exec > >(tee -a /var/log/lab-install.log) 2>&1
cd /opt/lab-src
ROLE=$(<role)
# setup.sh sets up key-only SSH for the sudo user: the Pi's first normal user.
SUDO_USER=$(getent passwd 1000 | cut -d: -f1) ./setup.sh "$ROLE" $(<args)
while read -r svc; do
  [[ -n $svc ]] && LAB_RECONNECT=no /usr/local/sbin/labctl break "$svc"
done < on
systemctl disable lab-install.service
echo "lab-install: $ROLE installed"
if [[ $ROLE == hub ]]; then
  echo "lab-install: rebooting so the hub's random MAC and 'no hostname' take effect"
  systemctl --no-block reboot
fi
EOF

cat > "$MNT/lab/lab-install.service" <<'EOF'
[Unit]
Description=Install the lab role (lab/card_role.sh)
Wants=network-online.target
After=network-online.target cloud-final.service ssh.service

[Service]
Type=oneshot
ExecStart=/opt/lab-src/install-role.sh
TimeoutStartSec=15min

[Install]
WantedBy=multi-user.target
EOF

# The hook runs as root in a minimal boot (no network). Whatever happens, it removes itself
# from cmdline.txt, so the Pi never gets stuck booting into it.
cat > "$MNT/lab-firstrun.sh" <<'EOF'
#!/bin/bash
B=/boot/firmware
cleanup() {
  sed -i -E 's/ ?systemd\.(run|run_success_action|run_failure_action)=[^ ]*//g; s/ ?systemd\.unit=kernel-command-line\.target//' "$B/cmdline.txt"
  rm -rf "$B/lab" "$B/lab-firstrun.sh"
  sync
}
trap cleanup EXIT
set -e
rm -rf /opt/lab-src
mkdir -p /opt/lab-src
cp -r "$B/lab/." /opt/lab-src/
chown -R root:root /opt/lab-src
chmod 755 /opt/lab-src/setup.sh /opt/lab-src/labctl /opt/lab-src/install-role.sh
install -m 0644 /opt/lab-src/lab-install.service /etc/systemd/system/lab-install.service
ln -sf /etc/systemd/system/lab-install.service /etc/systemd/system/multi-user.target.wants/lab-install.service
exit 0
EOF

CMD=$(head -n1 "$MNT/cmdline.txt" | sed -E 's/ ?systemd\.(run|run_success_action|run_failure_action)=[^ ]*//g; s/ ?systemd\.unit=kernel-command-line\.target//')
printf '%s systemd.run=/boot/firmware/lab-firstrun.sh systemd.run_success_action=reboot systemd.run_failure_action=reboot systemd.unit=kernel-command-line.target\n' "$CMD" > "$MNT/cmdline.txt"
sync

echo "DONE: the card will install the '$ROLE' role on its next boot${ON[*]:+, with ${ON[*]} on}."
echo "  It boots, reboots, then installs once online. Check on the Pi: journalctl -u lab-install"
if [[ -z $BOOT ]]; then
  :  # --to-dir: nothing to unmount
elif command -v udisksctl >/dev/null && udisksctl unmount -b "$BOOT" >/dev/null 2>&1; then
  echo "Unmounted $BOOT; safe to remove the card."
else
  echo "Unmount $BOOT (eject the card) before removing it."
fi
