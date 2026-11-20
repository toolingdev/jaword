#!/bin/sh
# Runs inside the vault container as root. Idempotent.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get -y -qq upgrade >/dev/null
apt-get -y -qq install ca-certificates curl openssh-client sqlite3 unattended-upgrades >/dev/null

# Nothing but the vault should listen in here.
for svc in ssh ssh.socket postfix; do systemctl disable --now "$svc" >/dev/null 2>&1 || true; done

id jaword >/dev/null 2>&1 || useradd --system --home-dir /var/lib/jaword --shell /usr/sbin/nologin jaword
install -d -m 0755 /etc/jaword /usr/local/share/doc/jaword
install -m 0755 /root/stage/jawordd /usr/local/bin/jawordd
install -m 0755 /root/stage/jaword /usr/local/bin/jaword
install -m 0644 /root/stage/jawordd.service /etc/systemd/system/jawordd.service
[ -f /etc/jaword/jawordd.env ] || : > /etc/jaword/jawordd.env
rm -rf /root/stage

if [ ! -f /etc/apt/sources.list.d/tailscale.list ]; then
  curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg -o /usr/share/keyrings/tailscale-archive-keyring.gpg
  curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list -o /etc/apt/sources.list.d/tailscale.list
  apt-get update -qq
fi
apt-get -y -qq install tailscale >/dev/null

systemctl daemon-reload
systemctl enable --now jawordd >/dev/null 2>&1
sleep 1
systemctl is-active jawordd
