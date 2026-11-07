#!/usr/bin/env bash
# Let teammates reach the lab from home (#199): this Pi becomes a Tailscale subnet router for
# the hotspot subnet (RSH-dork_unit), so a teammate's laptop on the tailnet can reach every
# device on it as if it were on the hotspot. The Pi 5 router stays as it is.
#
#   sudo lab/tailscale/setup_pi.sh               # install Tailscale if needed, advertise the subnet
#   lab/tailscale/setup_pi.sh --print-only       # show the subnet and the command, change nothing
#   sudo lab/tailscale/setup_pi.sh remove        # log out, stop Tailscale, forwarding off
#
# Only the subnet this Pi is on is advertised, and only if it is private (RFC 1918) and a /24
# or smaller, the same limits as the scan guardrail. Never an exit node, never other routes.
# Teammates show up on the lab as this Pi's address (SNAT), so the fakes see a private peer and
# replies need no route back. Login goes through the URL that `tailscale up` prints: there is
# no auth key, so nothing secret is stored anywhere.
#
# Use the camera Pi (pi2): its default services are all TCP. A teammate reaching the subnet
# router's *own* address arrives from a 100.x tailnet address, and the fake SSDP responder
# only answers private peers, so on the hub it would look different from home.
set -euo pipefail

HOSTNAME_TS=bilet-lab
SYSCTL_CONF=${BILET_SYSCTL_CONF:-/etc/sysctl.d/99-bilet-tailscale.conf}

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'setup_pi.sh: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# "NETWORK DEVICE ADDRESS" of the one network this Pi uses, or a refusal on stderr.
detect_subnet() {
  local routes addrs dev
  routes=$(ip -4 -j route show default) || die "ip route failed"
  dev=$(python3 -I -c '
import json, sys
devs = sorted({r["dev"] for r in json.loads(sys.argv[1] or "[]") if r.get("dev")})
if len(devs) != 1:
    sys.exit("no default route" if not devs else "on several networks at once: " + ", ".join(devs))
print(devs[0])' "$routes") || die "can't tell which network is the hotspot"
  addrs=$(ip -4 -j addr show dev "$dev") || die "ip addr failed"
  python3 -I -c '
import ipaddress, json, sys
dev = sys.argv[2]
found = [a["local"] + "/" + str(a["prefixlen"]) for link in json.loads(sys.argv[1] or "[]")
         for a in link.get("addr_info", []) if a.get("family") == "inet" and a.get("local")]
if not found:
    sys.exit(f"{dev} has no IPv4 address")
iface = ipaddress.ip_interface(found[0])
net = iface.network
home = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
if not any(net.subnet_of(h) for h in home):
    sys.exit(f"{net} on {dev} is not a private RFC 1918 network, so not our hotspot")
if net.num_addresses > 256:
    sys.exit(f"{net} on {dev} is larger than a /24, so not our hotspot (venue network?)")
print(net, dev, iface.ip)' "$addrs" "$dev" || die "refusing to advertise this network"
}

# The reverse-DNS zone for split DNS, e.g. 50.168.192.in-addr.arpa for 192.168.50.0/24.
reverse_zone() {
  python3 -I -c '
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1])
octets = str(net.network_address).split(".")[: max(1, net.prefixlen // 8)]
print(".".join(reversed(octets)) + ".in-addr.arpa")' "$1"
}

up_args() {
  printf '%s\n' up --reset "--hostname=$HOSTNAME_TS" "--advertise-routes=$1" \
    --snat-subnet-routes=true --accept-routes=false --accept-dns=false
}

install_tailscale() {
  command -v tailscale >/dev/null && return 0
  say "Installing Tailscale from its Debian repository (about 30 MB over the hotspot's uplink)"
  local codename
  codename=$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")
  [[ $codename =~ ^[a-z]+$ ]] || die "can't read the Debian release from /etc/os-release"
  curl -fsSL "https://pkgs.tailscale.com/stable/debian/$codename.noarmor.gpg" \
    -o /usr/share/keyrings/tailscale-archive-keyring.gpg
  curl -fsSL "https://pkgs.tailscale.com/stable/debian/$codename.tailscale-keyring.list" \
    -o /etc/apt/sources.list.d/tailscale.list
  apt-get update -q
  apt-get install -y -q tailscale
}

remove() {
  if command -v tailscale >/dev/null; then
    say "Logging out: this Pi leaves the tailnet and the route goes away"
    tailscale logout || true
    systemctl disable --now --quiet tailscaled || true
  fi
  rm -f "$SYSCTL_CONF"
  sysctl -q -w net.ipv4.ip_forward=0 || true
  say "Done. Tailscale is still installed: sudo apt purge tailscale removes it."
}

main() {
  local print_only=0
  case "${1:-}" in
  -h | --help) usage ;;
  remove)
    [[ $# -eq 1 ]] || usage 1
    [[ $(id -u) -eq 0 ]] || die "run as root: sudo $0 remove"
    remove
    return
    ;;
  --print-only) print_only=1 ;;
  "") ;;
  *) usage 1 ;;
  esac

  local net dev addr
  read -r net dev addr < <(detect_subnet) || exit 1
  local -a args
  mapfile -t args < <(up_args "$net")
  say "This Pi is $addr on $dev. Advertising $net and nothing else."
  if ((print_only)); then
    printf 'tailscale %s\n' "${args[*]}"
    return
  fi
  [[ $(id -u) -eq 0 ]] || die "run as root: sudo $0"

  install_tailscale
  say "IPv4 forwarding on (needed to route for the tailnet), kept across reboots"
  printf '# lab/tailscale/setup_pi.sh (#199): subnet router for the lab hotspot\nnet.ipv4.ip_forward = 1\n' \
    >"$SYSCTL_CONF"
  sysctl -q -p "$SYSCTL_CONF"
  systemctl enable --now --quiet tailscaled

  say "Joining the tailnet. If a URL appears, open it on any device and log in."
  tailscale "${args[@]}"

  cat <<EOM

Subnet router up. In the Tailscale admin console (https://login.tailscale.com/admin/machines):
  1. $HOSTNAME_TS -> Edit route settings -> approve $net.
  2. $HOSTNAME_TS -> Disable key expiry, so the route doesn't vanish in 180 days.
  3. Invite each teammate as a user (Settings -> Users -> Invite). Sharing the machine is
     not enough: a shared node doesn't share its subnet routes.
  4. Optional, so remote scans see hostnames: DNS -> Add nameserver -> Custom, the hotspot
     router's address, "Restrict to domain" $(reverse_zone "$net").
Teammates: lab/tailscale/README.md.
EOM
}

main "$@"
