#!/bin/sh
# Install the host-side pieces of the production SIEM (Linux + systemd, run as root):
#   - siem-firewall.service: DOCKER-USER source restrictions, re-applied after every Docker start
#   - siem-job@.service + timers: sync, SHA-256 manifest, monthly report, backup
#
#   sudo deploy/install.sh              # install / update and start everything
#   sudo deploy/install.sh --uninstall
#
# The units are written with this checkout's path, so the repo can live anywhere (e.g. /opt/siem).
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
UNITS=/etc/systemd/system
TIMERS="sync-assets sync-web manifest-create manifest-verify monthly-report backup"

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd not found: use deploy/cron/siem.cron instead" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
  for t in $TIMERS; do systemctl disable --now "siem-$t.timer" 2>/dev/null || true; done
  systemctl disable --now siem-firewall.service 2>/dev/null || true
  rm -f "$UNITS/siem-firewall.service" "$UNITS/siem-job@.service"
  for t in $TIMERS; do rm -f "$UNITS/siem-$t.timer"; done
  systemctl daemon-reload
  echo "uninstalled"
  exit 0
fi

[ -f "$ROOT/.env" ] || { echo "$ROOT/.env missing: copy .env.example and fill the Production section" >&2; exit 1; }
chmod 600 "$ROOT/.env"
chmod +x "$ROOT/deploy/siem-job.sh" "$ROOT/deploy/backup.sh" "$ROOT/deploy/firewall/siem-docker-user.sh"

for f in "$ROOT"/deploy/systemd/*; do
  sed "s#/opt/siem#$ROOT#g" "$f" > "$UNITS/$(basename "$f")"
done
systemctl daemon-reload

systemctl enable --now docker.service
systemctl enable siem-firewall.service
systemctl restart siem-firewall.service
for t in $TIMERS; do systemctl enable --now "siem-$t.timer"; done

echo
systemctl --no-pager status siem-firewall.service | head -n 5
echo
systemctl --no-pager list-timers 'siem-*'
