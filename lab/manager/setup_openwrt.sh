#!/bin/sh
# Install the lab manager (#155) on the OpenWrt router (the Pi 5). POSIX sh: OpenWrt has
# no bash. Run it as root on the router, from a copy of lab/:
#
#   scp -O -r lab root@<pi5>:/tmp/lab        (on the laptop; -O because dropbear has no sftp)
#   sh /tmp/lab/manager/setup_openwrt.sh      (on the router)
#   sh /tmp/lab/manager/setup_openwrt.sh remove
#
# It needs python3 (a few MB over the router's uplink; OpenWrt 25.12 uses apk, older ones opkg):
#   apk add python3-light python3-email python3-urllib python3-logging python3-codecs
# It uses OpenWrt's own dropbear client, so no openssh packages. It runs as the user
# labmanager and listens on 127.0.0.1:8090 only, so it never shows up in a scan of the hotspot.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
DIR=/opt/lab-manager
CONF=/etc/lab-manager
STATE=$CONF/state
INIT=/etc/init.d/lab-manager

die() { echo "setup_openwrt.sh: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root on the router"
[ -f /etc/openwrt_release ] || die "this is for the OpenWrt router; on other Linux use setup_manager.sh"

if [ "${1:-}" = remove ]; then
	[ -x $INIT ] && { $INIT stop || true; $INIT disable || true; }
	rm -f $INIT
	rm -rf $DIR
	echo "Removed. Kept on purpose: $CONF (your Pi list and the key)."
	exit 0
fi
[ $# -eq 0 ] || die "usage: sh setup_openwrt.sh [remove]"

# python3-light alone lacks email, urllib, logging and the idna codec, which http.server needs.
if command -v apk >/dev/null; then
	PKG_HINT="apk update && apk add python3-light python3-email python3-urllib python3-logging python3-codecs"
else
	PKG_HINT="opkg update && opkg install python3-light python3-email python3-urllib python3-logging python3-codecs"
fi
if ! command -v python3 >/dev/null; then
	die "python3 is missing. Install it with: $PKG_HINT"
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || die "python3 3.11 or newer is needed"
python3 -I -c 'import http.server, concurrent.futures, ipaddress, secrets, dataclasses, encodings.idna' 2>/dev/null \
	|| die "python3 lacks a module the manager needs. Install: $PKG_HINT"
command -v dbclient >/dev/null || die "dbclient (dropbear's SSH client) is missing"
command -v dropbearkey >/dev/null || die "dropbearkey is missing"

# A system user that owns only its state folder. functions.sh reads IPKG_INSTROOT unset (set -u).
IPKG_INSTROOT=${IPKG_INSTROOT:-}
. /lib/functions.sh
if ! user_exists labmanager; then
	group_exists labmanager || group_add labmanager 4955
	user_add labmanager 4955 4955 "lab manager" "$STATE" /bin/false
fi

mkdir -p $DIR $CONF $STATE/.ssh
cp "$HERE/manager.py" "$HERE/../services.tsv" "$HERE/../presets.tsv" $DIR/
cp "$HERE/README.md" $DIR/ 2>/dev/null || true
chmod 0644 $DIR/*
[ -e $CONF/pis.conf ] || cp "$HERE/pis.conf.example" $CONF/pis.conf
chmod 0644 $CONF/pis.conf

if [ ! -s $STATE/id_dropbear ]; then
	dropbearkey -t ed25519 -f $STATE/id_dropbear >/dev/null 2>&1 \
		|| dropbearkey -t ecdsa -s 256 -f $STATE/id_dropbear >/dev/null
fi
chown -R labmanager:labmanager $STATE
chmod 0700 $STATE $STATE/.ssh
chmod 0600 $STATE/id_dropbear

cp "$HERE/lab-manager.init" $INIT
chmod 0755 $INIT
$INIT enable
$INIT restart

PUB=$(dropbearkey -y -f $STATE/id_dropbear | grep -E '^(ssh-|ecdsa-)')
cat <<EOM

Lab manager installed. Next:
  1. Put the lab Pis' IPs in $CONF/pis.conf (NAME IP per line), then: $INIT restart
  2. Save this public key as lab-manager.pub and copy it to each lab Pi:
$PUB
     then on each Pi: sudo lab/setup.sh <role> --manager-key lab-manager.pub
  3. From the laptop: ssh -L 8090:127.0.0.1:8090 root@<this router>, then open http://127.0.0.1:8090/
EOM
