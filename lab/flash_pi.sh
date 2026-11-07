#!/usr/bin/env bash
# Flash Raspberry Pi OS Lite 64-bit (headless) to an SD card and preconfigure first boot
# with cloud-init: hostname, user, SSH keys, SSH on. No Wi-Fi is configured.
#
# Usage: sudo lab/flash_pi.sh <device> <hostname> [options]
#   sudo lab/flash_pi.sh /dev/sdb pi2
#   sudo lab/flash_pi.sh /dev/mmcblk0 pi3      # built-in card slot
# Options:
#   --user NAME      login user (default: pi)
#   --pubkey FILE    SSH public key to authorise; repeatable (default: every ~/.ssh/*.pub of the sudo user)
#   --image FILE     Pi OS .img.xz (default: newest in out/pi-images/, downloaded if none)
#   --yes            skip the "type the hostname to confirm" prompt
# Env: PI_PW_HASH    precomputed SHA-512 crypt hash; otherwise you are asked for a password.
set -euo pipefail
source "$(dirname "$0")/_card.sh"

[[ $EUID -eq 0 ]] || die "run with sudo"
[[ $# -ge 2 ]] || { sed -n '2,14p' "$0"; exit 1; }

DEV=$1; HOST=$2; shift 2
USER_NAME=pi; IMAGE=; YES=0; KEYFILES=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --user)   USER_NAME=$2; shift 2 ;;
    --pubkey) KEYFILES+=("$2"); shift 2 ;;
    --image)  IMAGE=$2; shift 2 ;;
    --yes)    YES=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done

REPO=$(cd "$(dirname "$0")/.." && pwd)
IMG_DIR="$REPO/out/pi-images"
[[ $HOST =~ ^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$ ]] || die "bad hostname '$HOST'"
[[ $USER_NAME =~ ^[a-z_][a-z0-9_-]{0,30}$ ]] || die "bad user name '$USER_NAME'"
check_card "$DEV"
load_pubkeys "${KEYFILES[@]}"
KEYS_YAML=""; for l in "${PUBKEY_LINES[@]}"; do KEYS_YAML+="      - \"$l\""$'\n'; done

# --- Image: use local copy or download + verify the latest Lite arm64 -----------------
if [[ -z $IMAGE ]]; then
  IMAGE=$(ls -1t "$IMG_DIR"/*raspios*arm64-lite.img.xz 2>/dev/null | head -n1 || true)
  if [[ -z $IMAGE ]]; then
    echo "== Downloading latest Raspberry Pi OS Lite 64-bit"
    mkdir -p "$IMG_DIR"
    URL=$(curl -sSfLI -o /dev/null -w '%{url_effective}' https://downloads.raspberrypi.com/raspios_lite_arm64_latest)
    (cd "$IMG_DIR" && curl -sSfLO "$URL.sha256" && curl -fLO "$URL" && sha256sum -c "$(basename "$URL").sha256")
    chown -R "${SUDO_USER:-root}": "$IMG_DIR"
    IMAGE="$IMG_DIR/$(basename "$URL")"
  fi
fi
[[ -f $IMAGE ]] || die "image $IMAGE not found"
if [[ -f $IMAGE.sha256 ]]; then
  echo "== Verifying $(basename "$IMAGE")"
  (cd "$(dirname "$IMAGE")" && sha256sum -c --quiet "$(basename "$IMAGE").sha256") || die "image checksum mismatch"
fi

[[ -n ${PI_PW_HASH:-} ]] || PI_PW_HASH=$(ask_password_hash "Password for '$USER_NAME' on $HOST")
confirm_erase "$DEV" "$HOST" "$(basename "$IMAGE")" "$YES"

# --- Flash ---------------------------------------------------------------------------
unmount_all "$DEV"
wipefs -aq "$DEV"
echo "== Writing image"
xz -dc "$IMAGE" | dd of="$DEV" bs=4M iflag=fullblock oflag=direct status=progress
sync
partprobe "$DEV" 2>/dev/null || true; udevadm settle; sleep 3
unmount_all "$DEV"

BOOT=$(part "$DEV" 1)
[[ $(lsblk -no LABEL "$BOOT") == bootfs ]] || die "can't find bootfs partition after flashing"

# --- First-boot config (cloud-init) --------------------------------------------------
MNT=$(mktemp -d); trap 'umount "$MNT" 2>/dev/null; rmdir "$MNT" 2>/dev/null' EXIT
mount "$BOOT" "$MNT"
cat > "$MNT/user-data" <<EOF
#cloud-config
hostname: $HOST
manage_etc_hosts: true
timezone: Europe/Bucharest
keyboard:
  model: pc105
  layout: us
users:
  - name: $USER_NAME
    groups: users,adm,dialout,audio,netdev,video,plugdev,cdrom,games,input,gpio,spi,i2c,render,sudo
    shell: /bin/bash
    lock_passwd: false
    passwd: "$PI_PW_HASH"
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
$KEYS_YAML
enable_ssh: true
ssh_pwauth: true
runcmd:
  - [ systemctl, enable, --now, ssh ]
EOF
touch "$MNT/ssh"   # legacy "enable SSH" flag, harmless if unused
sync; umount "$MNT"

echo
lsblk -o NAME,SIZE,FSTYPE,LABEL "$DEV"
echo "DONE: $HOST is ready (user '$USER_NAME'). It has no Wi-Fi configured yet."
