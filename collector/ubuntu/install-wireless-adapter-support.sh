#!/usr/bin/env bash
set -euo pipefail

RTW89_REPOSITORY="${RTW89_REPOSITORY:-https://github.com/morrownr/rtw89.git}"
RTW89_REF="${RTW89_REF:-08b8d326937a200a706ec9c501374eec15835b5a}"
SOURCE_DIR="${SOURCE_DIR:-/usr/src/metro-rtw89}"
SUPPORTED_RTW89_USB_IDS=(
  "0bda:b832"
  "0bda:b83a"
  "0bda:b852"
  "0bda:b85a"
  "0bda:a85b"
)

[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 2; }

has_usb_id() {
  local expected="$1"
  lsusb | awk '{print tolower($6)}' | grep -Fxq "$expected"
}

supported_device_present=false
for usb_id in "${SUPPORTED_RTW89_USB_IDS[@]}"; do
  if has_usb_id "$usb_id"; then
    supported_device_present=true
    echo "detected supported RTW89 USB adapter: ${usb_id}"
  fi
done

if [[ "$supported_device_present" != "true" ]]; then
  echo "no supported RTL8832BU/RTL8852BU USB adapter detected"
  exit 3
fi

apt-get update
apt-get install -y --no-install-recommends \
  bc build-essential dkms git iw libelf-dev linux-headers-"$(uname -r)" \
  mokutil rfkill usb-modeswitch

if [[ -d "${SOURCE_DIR}/.git" ]]; then
  git -C "$SOURCE_DIR" fetch --prune origin
else
  install -d -m 755 "$(dirname "$SOURCE_DIR")"
  git clone "$RTW89_REPOSITORY" "$SOURCE_DIR"
fi
git -C "$SOURCE_DIR" checkout --detach "$RTW89_REF"

dkms install "$SOURCE_DIR"
make -C "$SOURCE_DIR" install_fw
install -m 644 "$SOURCE_DIR/rtw89.conf" /etc/modprobe.d/rtw89.conf
depmod -a
if modinfo rtw89_8852bu_git >/dev/null 2>&1; then
  modprobe rtw89_8852bu_git
else
  modprobe rtw89_8852bu
fi

echo "wireless adapter driver installation complete"
lsusb -t
iw dev
