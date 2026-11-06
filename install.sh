#!/usr/bin/env bash
# UnUnknownTun one-command installer. Run as root on each server:
#   bash <(curl -fsSL https://raw.githubusercontent.com/NPNTEI/SpoofTun/main/install.sh)
set -Eeuo pipefail
REPO="${UNUNKNOWNTUN_REPO:-NPNTEI/SpoofTun}"
REF="${UNUNKNOWNTUN_REF:-main}"
VER="3.7.0-preview.11"
FILE="UNUNKNOWNTUN-V3-INSTALLER-${VER}.sh"
BASE="https://raw.githubusercontent.com/${REPO}/${REF}"

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash install.sh" >&2; exit 1; }
if ! command -v curl >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq curl ca-certificates || { echo "curl is required." >&2; exit 1; }
fi
if ! command -v python3 >/dev/null 2>&1; then
    apt-get install -y -qq python3 || { echo "python3 is required." >&2; exit 1; }
fi

dir="$(mktemp -d /tmp/ununknowntun-install.XXXXXX)"
echo "Downloading ${FILE} ..."
curl -fL --retry 3 -o "$dir/$FILE" "${BASE}/${FILE}"
curl -fsSL --retry 3 -o "$dir/SHA256SUMS" "${BASE}/SHA256SUMS"
want="$(awk -v f="$FILE" '$2==f{print $1}' "$dir/SHA256SUMS")"
got="$(sha256sum "$dir/$FILE" | awk '{print $1}')"
[[ -n "$want" && "$want" == "$got" ]] || { echo "Checksum mismatch; aborting." >&2; exit 1; }
cd "$dir"
if [[ -r /dev/tty ]]; then exec bash "$FILE" "$@" </dev/tty; fi
exec bash "$FILE" "$@"
