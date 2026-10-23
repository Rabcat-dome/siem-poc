#!/bin/sh
# Run one scheduled SIEM job on the host, with settings from the repo's .env.
# Called by the systemd timers in deploy/systemd/ (or deploy/cron/siem.cron).
#
#   deploy/siem-job.sh sync-assets       OPNsense DHCP static mappings -> assets.csv     (every 15 min)
#   deploy/siem-job.sh sync-web          sources file -> web_categories.csv               (nightly)
#   deploy/siem-job.sh manifest-create   SHA-256 of new archive files                     (nightly)
#   deploy/siem-job.sh manifest-verify   re-hash every archived file -> OPS-02 on failure (monthly)
#   deploy/siem-job.sh monthly-report    RPT-01 for the previous month, by e-mail         (monthly)
#   deploy/siem-job.sh backup            MongoDB + config + OPNsense config.xml           (nightly)
#   deploy/siem-job.sh disk-check        disk usage of the data disk -> OPS-03 at DISK_WARN_PCT (hourly)
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
set -a; . ./.env; set +a

# results of the manifest and disk jobs go back into the SIEM so a failed check raises OPS-02 / OPS-03
SYSLOG_TARGET="${SIEM_HOST_IP:?set SIEM_HOST_IP}:${SYSLOG_HOST_PORT:-514}"
INSECURE=""
[ "${OPNSENSE_INSECURE:-false}" = "true" ] && INSECURE="--insecure"

case "${1:-}" in
  sync-assets)
    exec python3 tools/sync_assets.py --backend "${OPNSENSE_DHCP_BACKEND:-kea}" $INSECURE ;;
  sync-web)
    if [ -n "${OPNSENSE_URL:-}" ]; then
      exec python3 tools/sync_web_categories.py --opnsense $INSECURE
    fi
    exec python3 tools/sync_web_categories.py ;;
  manifest-create)
    exec python3 tools/log_manifest.py create "${ARCHIVE_DIR:?}" "${MANIFEST_DIR:?}" --syslog "$SYSLOG_TARGET" ;;
  manifest-verify)
    exec python3 tools/log_manifest.py verify "${ARCHIVE_DIR:?}" "${MANIFEST_DIR:?}" --syslog "$SYSLOG_TARGET" ;;
  monthly-report)
    GRAYLOG_URL="https://${SIEM_HOST_IP}:9000" GRAYLOG_CA_FILE="$ROOT/tls/ca.crt" \
    GRAYLOG_USER="${REPORT_USER:?}" GRAYLOG_PASSWORD="${REPORT_PASSWORD:?}" REPORT_FROM="${ALERT_FROM:-}" \
      exec python3 tools/monthly_report.py --out "${REPORT_DIR:-$ROOT/reports}" --email-to "${REPORT_EMAIL_TO:?}" ;;
  backup)
    exec "$ROOT/deploy/backup.sh" ;;
  disk-check)
    # DISK_CHECK_PATHS may list several mount points, separated by spaces
    exec python3 tools/disk_check.py ${DISK_CHECK_PATHS:-/var/lib/docker} --warn "${DISK_WARN_PCT:-75}" --syslog "$SYSLOG_TARGET" ;;
  *)
    echo "usage: $0 sync-assets|sync-web|manifest-create|manifest-verify|monthly-report|backup|disk-check" >&2
    exit 2 ;;
esac
