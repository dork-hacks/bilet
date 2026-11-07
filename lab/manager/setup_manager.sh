#!/usr/bin/env bash
# Install the lab manager (#155) on the Pi 5, the hotspot router. Not for the lab Pis.
#
#   sudo lab/manager/setup_manager.sh          install or update, then print the public key
#   sudo lab/manager/setup_manager.sh remove   stop it and remove it
#
# It listens on 127.0.0.1:8090 only. From the laptop:
#   ssh -L 8090:127.0.0.1:8090 <user>@<pi5>   and open http://127.0.0.1:8090/
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DIR=/opt/lab-manager
CONF_DIR=/etc/lab-manager
UNIT=/etc/systemd/system/lab-manager.service

die() { printf 'setup_manager.sh: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run with sudo"

if [[ ${1:-} == remove ]]; then
  systemctl disable --now --quiet lab-manager.service 2>/dev/null || true
  rm -f "$UNIT"
  rm -rf "$DIR"
  systemctl daemon-reload
  echo "Removed. Kept on purpose: $CONF_DIR (your Pi list) and the key in /var/lib/lab-manager."
  exit 0
fi
[[ $# -eq 0 ]] || die "usage: sudo lab/manager/setup_manager.sh [remove]"

command -v ssh >/dev/null || die "the ssh client is needed (apt install openssh-client)"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || die "python3 3.11 or newer is needed"

install -d -m 0755 "$DIR" "$CONF_DIR"
install -m 0644 "$HERE/manager.py" "$HERE/../services.tsv" "$HERE/../presets.tsv" "$DIR/"
install -m 0644 "$HERE/README.md" "$DIR/" 2>/dev/null || true
[[ -e $CONF_DIR/pis.conf ]] || install -m 0644 "$HERE/pis.conf.example" "$CONF_DIR/pis.conf"
install -m 0644 "$HERE/lab-manager.service" "$UNIT"
systemctl daemon-reload
systemctl enable --quiet lab-manager.service
systemctl restart lab-manager.service

for _ in 1 2 3 4 5; do [[ -s /var/lib/lab-manager/id_ed25519.pub ]] && break; sleep 1; done
cat <<EOM

Lab manager installed. Next:
  1. Put the lab Pis' IPs in $CONF_DIR/pis.conf, then: sudo systemctl restart lab-manager
  2. Copy this public key to each lab Pi and run there:
       sudo lab/setup.sh <role> --manager-key lab-manager.pub
$(cat /var/lib/lab-manager/id_ed25519.pub 2>/dev/null || echo "     (no key yet: check 'journalctl -u lab-manager')")
  3. From the laptop: ssh -L 8090:127.0.0.1:8090 <user>@<this Pi>, then open http://127.0.0.1:8090/
EOM
