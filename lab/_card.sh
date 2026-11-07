# Shared helpers for the lab flashing scripts. Source it, don't run it.

die() { echo "ERROR: $*" >&2; exit 1; }

# Refuse anything that isn't a removable SD card (never a system disk).
check_card() {
  local dev=$1 rm size
  [[ -b $dev && $(lsblk -dno TYPE "$dev") == disk ]] || die "$dev is not a whole disk"
  rm=$(lsblk -dno RM "$dev" | tr -d ' ')
  [[ $rm == 1 || $dev == /dev/mmcblk* ]] || die "$dev is not removable; refusing"
  size=$(lsblk -bdno SIZE "$dev" | tr -d " ")
  (( size < 300 * 1000**3 )) || die "$dev is larger than 300 GB, doesn't look like an SD card"
  if lsblk -nro MOUNTPOINTS "$dev" | grep -qxE '/|/boot|/boot/efi|/home'; then die "$dev holds a system mount"; fi
}

# Unmount every partition of a disk (also undoes desktop automounts).
unmount_all() { local p; for p in $(lsblk -nrpo NAME "$1" | tail -n +2); do umount "$p" 2>/dev/null || true; done; }

# Nth partition of a disk (1-based), e.g. part /dev/sda 2 -> /dev/sda2, /dev/mmcblk0 2 -> /dev/mmcblk0p2
part() { lsblk -nrpo NAME "$1" | sed -n "$(( $2 + 1 ))p"; }

# Read a password twice from the terminal; prints a SHA-512 crypt hash.
ask_password_hash() {
  local p1 p2
  while :; do
    read -rsp "$1: " p1 </dev/tty; echo >&2
    read -rsp "Repeat: " p2 </dev/tty; echo >&2
    [[ -n $p1 && $p1 == "$p2" ]] && break
    echo "Empty or mismatched, try again." >&2
  done
  printf '%s' "$p1" | openssl passwd -6 -stdin
}

# Collect SSH public keys: the given files, or every ~/.ssh/*.pub of the sudo user.
# Sets the global array PUBKEY_LINES.
load_pubkeys() {
  local home k line files=("$@")
  if [[ ${#files[@]} -eq 0 ]]; then
    home=$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)
    shopt -s nullglob; files=("$home"/.ssh/*.pub); shopt -u nullglob
  fi
  [[ ${#files[@]} -gt 0 ]] || die "no SSH public key found; pass --pubkey FILE"
  PUBKEY_LINES=()
  for k in "${files[@]}"; do
    [[ -f $k ]] || die "missing $k"
    line=$(head -n1 "$k")
    [[ $line =~ ^(ssh-|ecdsa-|sk-) ]] || die "$k is not an SSH public key"
    PUBKEY_LINES+=("$line")
  done
}

# Ask the user to type the hostname before erasing (skipped with --yes).
confirm_erase() {
  local dev=$1 host=$2 what=$3 yes=$4 ans
  echo
  lsblk -o NAME,SIZE,MODEL,FSTYPE,LABEL "$dev"
  echo "About to ERASE $dev and install $what as '$host'."
  [[ $yes -eq 1 ]] && return
  read -rp "Type the hostname ($host) to continue: " ans </dev/tty
  [[ $ans == "$host" ]] || die "aborted"
}
