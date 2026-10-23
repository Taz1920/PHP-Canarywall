#!/bin/sh
set -e

. /etc/os-release
CODENAME="${VERSION_CODENAME:-}"
if [ -z "$CODENAME" ]; then
  case "$VERSION_ID" in
    8) CODENAME=jessie ;;
    9) CODENAME=stretch ;;
    10) CODENAME=buster ;;
    11) CODENAME=bullseye ;;
  esac
fi

case "$CODENAME" in
  jessie|stretch|buster|bullseye)
    sed -i 's|deb.debian.org|archive.debian.org|g' /etc/apt/sources.list
    sed -i 's|security.debian.org|archive.debian.org|g' /etc/apt/sources.list
    sed -i '/-updates/d' /etc/apt/sources.list
    cat > /etc/apt/apt.conf.d/99archive <<APTEOF
Acquire::Check-Valid-Until "false";
Acquire::AllowInsecureRepositories "true";
Acquire::AllowDowngradeToInsecureRepositories "true";
APTEOF
    ;;
esac

apt-get update
