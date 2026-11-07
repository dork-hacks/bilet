#!/usr/bin/env bash
# Install one lab role on a Raspberry Pi 4 (Raspberry Pi OS Lite 64-bit, bookworm).
#
#   sudo lab/setup.sh camera|server|hub [--with-packages]
#   sudo lab/setup.sh remove
#
# camera  pi2: telnet (BusyBox banner, 2323), "Camera Login" web page, FTP "vsFTPd 2.3.4"
#         (a camera that uploads clips over FTP); RTSP as a toggle
# hub     pi3: MQTT + no vendor/hostname (UNKNOWN_DEVICE); SSDP, SNMP, JetDirect as toggles
# server  optional third device (#128): nothing on by default; fake Redis and Samba
#         (no shares) as toggles, for the "new device" / "new open port" demo
#
# --with-packages  apt-installs the real daemons a role can toggle (samba / snmpd).
#                  Do this at home: hotspot data is limited.
# remove           switch everything off and undo the install ("switch everything off afterwards").
#
# Every role also gets key-only SSH (SSH_OPEN, 0 points) if you have an authorized key.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LAB_DIR=/opt/lab
STATE_DIR=/etc/lab
UNIT_DIR=/etc/systemd/system

say() { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() { printf 'setup.sh: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

lab_units() { # every lab-fake@ instance, loaded or just enabled
  { systemctl list-units --all --plain --no-legend 'lab-fake@*' 2>/dev/null | awk '{ print $1 }'
    systemctl list-unit-files --no-legend 'lab-fake@*' 2>/dev/null | awk '$1 ~ /@.+\./ { print $1 }'
  } | sort -u
}

backup_once() { [[ -f $1 && ! -f $1.lab-backup ]] && cp -p "$1" "$1.lab-backup" || true; }
restore_backup() { [[ -f $1.lab-backup ]] && mv -f "$1.lab-backup" "$1" || true; }

configure_samba() {
  dpkg -s samba >/dev/null 2>&1 || return 0
  say "Samba: no shares, no guest access (SMB_EXPOSED toggle, off by default)"
  backup_once /etc/samba/smb.conf
  cat >/etc/samba/smb.conf <<'EOF'
# Lab config (lab/setup.sh): Samba answers on 139/445 but shares nothing.
[global]
   workgroup = WORKGROUP
   server string = Office server
   server role = standalone server
   map to guest = never
   restrict anonymous = 2
   server min protocol = SMB2
   load printers = no
   printing = bsd
   printcap name = /dev/null
   disable spoolss = yes
   log level = 0
EOF
  testparm -s >/dev/null 2>&1 || die "testparm rejected the lab smb.conf"
  systemctl disable --now --quiet smbd nmbd 2>/dev/null || true
}

configure_snmpd() {
  dpkg -s snmpd >/dev/null 2>&1 || return 0
  say "snmpd: no communities and no users (SNMP_EXPOSED toggle, off by default)"
  backup_once /etc/snmp/snmpd.conf
  cat >/etc/snmp/snmpd.conf <<'EOF'
# Lab config (lab/setup.sh): listens on UDP 161 but grants no access at all.
# No rocommunity/rwcommunity and no SNMPv3 users: SNMPv1/v2c requests are dropped and
# SNMPv3 requests only get the engine-discovery report, which is what nmap -sV sees.
agentaddress udp:161
EOF
  systemctl disable --now --quiet snmpd 2>/dev/null || true
}

ssh_key_only() {
  local user=${SUDO_USER:-} keys
  [[ -n $user && $user != root ]] || { warn "run via sudo from your normal user to set up key-only SSH; skipped"; return 0; }
  keys=$(getent passwd "$user" | cut -d: -f6)/.ssh/authorized_keys
  if [[ ! -s $keys ]]; then
    warn "$user has no $keys, so password SSH stays on (otherwise you'd be locked out). Add a key and re-run."
    return 0
  fi
  say "SSH: key-only login (SSH_OPEN, 0 points)"
  printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n' \
    >/etc/ssh/sshd_config.d/50-lab-key-only.conf
  sshd -t || die "sshd rejected the key-only config"
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
}

install_role() {
  local role=$1 with_packages=$2

  python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null \
    || die "python3 3.11 or newer is needed (Raspberry Pi OS bookworm has it)"
  if (( $(ip -4 route show default | wc -l) > 1 )); then
    warn "more than one default route: the Pi should be on the team hotspot only"
  fi

  if [[ -r $STATE_DIR/role && $(<"$STATE_DIR/role") != "$role" ]]; then
    say "Switching role from $(<"$STATE_DIR/role") to $role: stopping the old role's services"
  fi
  for unit in $(lab_units); do systemctl disable --now --quiet "$unit" || true; done

  if [[ $with_packages == yes ]]; then
    local pkgs=()
    [[ $role == server ]] && pkgs+=(samba)
    [[ $role == hub ]] && pkgs+=(snmpd)
    if (( ${#pkgs[@]} )); then
      say "Installing ${pkgs[*]} (needs internet)"
      apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "${pkgs[@]}"
    fi
  fi

  say "Installing the lab files ($role)"
  install -d -m 0755 "$LAB_DIR" "$STATE_DIR"
  install -m 0644 "$HERE/fakes/fakesvc.py" "$HERE/services.tsv" "$HERE/README.md" "$LAB_DIR/"
  install -m 0755 "$HERE/labctl" /usr/local/sbin/labctl
  install -m 0644 "$HERE/systemd/lab-fake@.service" "$HERE/systemd/lab-leds.service" "$UNIT_DIR/"
  echo "$role" >"$STATE_DIR/role"
  systemctl daemon-reload

  [[ $role == server ]] && configure_samba
  [[ $role == hub ]] && configure_snmpd
  ssh_key_only
  systemctl enable --quiet lab-leds.service

  say "Applying the default lab for $role"
  LAB_RECONNECT=no /usr/local/sbin/labctl reset

  cat <<EOF

Done. Useful commands on this Pi:
  labctl status              what is on, with catalog codes and points
  sudo labctl fix telnet     turn one weak service off (LED goes green when all are off)
  sudo labctl break telnet   turn it back on
  sudo labctl reset          back to the default lab
EOF
  if [[ $role == hub ]]; then
    echo
    echo "Hub: reboot (or reconnect Wi-Fi) so the random MAC and 'no hostname' take effect."
  fi
}

remove_all() {
  say "Stopping every lab service"
  [[ -x /usr/local/sbin/labctl ]] && /usr/local/sbin/labctl leds-restore >/dev/null 2>&1 || true
  for unit in $(lab_units) lab-leds.service; do systemctl disable --now --quiet "$unit" 2>/dev/null || true; done

  if [[ -r $STATE_DIR/role && $(<"$STATE_DIR/role") == hub ]] && command -v nmcli >/dev/null; then
    local con
    con=$(nmcli -t -f NAME,TYPE connection show --active | awk -F: '$2 == "802-11-wireless" { print $1; exit }')
    if [[ -n $con ]]; then
      say "Hub: giving the Wi-Fi its real MAC and hostname back (takes effect on reconnect)"
      nmcli connection modify "$con" 802-11-wireless.cloned-mac-address permanent \
        ipv4.dhcp-send-hostname yes ipv6.dhcp-send-hostname yes || true
    fi
  fi

  if [[ -f /etc/samba/smb.conf.lab-backup ]]; then
    systemctl disable --now --quiet smbd nmbd 2>/dev/null || true
    restore_backup /etc/samba/smb.conf
  fi
  if [[ -f /etc/snmp/snmpd.conf.lab-backup ]]; then
    systemctl disable --now --quiet snmpd 2>/dev/null || true
    restore_backup /etc/snmp/snmpd.conf
  fi

  rm -f "$UNIT_DIR/lab-fake@.service" "$UNIT_DIR/lab-leds.service" /usr/local/sbin/labctl
  rm -rf "$LAB_DIR" "$STATE_DIR"
  systemctl daemon-reload
  say "Removed. Kept on purpose: key-only SSH (/etc/ssh/sshd_config.d/50-lab-key-only.conf) and any apt packages."
}

main() {
  [[ $# -ge 1 ]] || usage 1
  [[ $1 == -h || $1 == --help ]] && usage 0
  [[ $EUID -eq 0 ]] || die "run with sudo"
  local cmd=$1 with_packages=no
  shift
  for arg in "$@"; do
    case $arg in
      --with-packages) with_packages=yes ;;
      *) die "unknown option '$arg'" ;;
    esac
  done
  case $cmd in
    camera | server | hub) install_role "$cmd" "$with_packages" ;;
    remove) remove_all ;;
    *) usage 1 ;;
  esac
}

main "$@"
