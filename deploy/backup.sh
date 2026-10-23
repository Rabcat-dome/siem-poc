#!/bin/sh
# Nightly backup of the SIEM's own state (NFR-07) and the OPNsense configuration (Q12).
#
#   graylog-mongodb.archive.gz   MongoDB dump: inputs, streams, pipelines, alerts, dashboards, users
#   siem-config.tar.gz[.enc]     graylog/ (rules, lookup CSVs), .env, tls/ (never the CA key in tls-ca/)
#   opnsense-config.xml          latest OPNsense config through its API (when OPNSENSE_URL is set)
#   SHA256SUMS                   checksums of the files above
#
# Log data is not copied here: OpenSearch keeps 90 days hot and the long-term archive lives on
# Synology (Q2, Q10). Restore steps are in README "Deploy production".
#
# Env (.env): BACKUP_DIR (required, e.g. the mounted Synology share), BACKUP_KEEP_DAYS (30),
#   BACKUP_PASSPHRASE (encrypts the config tarball, which holds .env secrets and the TLS key),
#   COMPOSE_FILE (docker-compose.prod.yml), OPNSENSE_URL / OPNSENSE_KEY / OPNSENSE_SECRET / OPNSENSE_INSECURE
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
set -a; . ./.env; set +a

DEST="${BACKUP_DIR:?set BACKUP_DIR}/$(date +%Y%m%d-%H%M%S)"
KEEP=${BACKUP_KEEP_DAYS:-30}
COMPOSE="docker compose -f ${COMPOSE_FILE:-docker-compose.prod.yml}"
umask 077
mkdir -p "$DEST"

# 1. Graylog configuration in MongoDB
$COMPOSE exec -T mongodb mongodump --archive --gzip --db graylog --quiet > "$DEST/graylog-mongodb.archive.gz"

# 2. repo configuration; encrypted when a passphrase is set because .env and tls/server.key are secrets
CONFIG="graylog .env"
[ -d tls ] && CONFIG="$CONFIG tls"
if [ -n "${BACKUP_PASSPHRASE:-}" ]; then
  tar -czf - $CONFIG | openssl enc -aes-256-cbc -pbkdf2 -salt -pass env:BACKUP_PASSPHRASE -out "$DEST/siem-config.tar.gz.enc"
else
  echo "warning: BACKUP_PASSPHRASE not set, config backup is not encrypted" >&2
  tar -czf "$DEST/siem-config.tar.gz" $CONFIG
fi

# 3. OPNsense config.xml (credentials go through stdin so they never show up in ps)
if [ -n "${OPNSENSE_URL:-}" ]; then
  K=""
  [ "${OPNSENSE_INSECURE:-false}" = "true" ] && K="-k"
  if printf 'user = "%s:%s"\n' "${OPNSENSE_KEY:?}" "${OPNSENSE_SECRET:?}" |
      curl -fsS $K --max-time 60 -K - -o "$DEST/opnsense-config.xml" "$OPNSENSE_URL/api/core/backup/download/this" &&
      grep -q "<opnsense>" "$DEST/opnsense-config.xml"; then
    :
  else
    echo "error: OPNsense config download failed" >&2
    rm -f "$DEST/opnsense-config.xml"
    FAILED=1
  fi
fi

# 4. checksums, so a restore can prove the files are intact
if command -v sha256sum >/dev/null 2>&1; then SUM="sha256sum"; else SUM="shasum -a 256"; fi
(cd "$DEST" && $SUM -- * > SHA256SUMS)

# 5. retention
find "${BACKUP_DIR}" -mindepth 1 -maxdepth 1 -type d -name '20*' -mtime +"$KEEP" -exec rm -rf {} +

echo "backup written to $DEST:"
ls -l "$DEST" | tail -n +2
exit "${FAILED:-0}"
