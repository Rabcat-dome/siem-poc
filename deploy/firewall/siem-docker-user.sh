#!/bin/sh
# Restrict who may reach the SIEM's Docker-published ports.
#
# Docker publishes ports with DNAT in PREROUTING, so the packets are FORWARDed to the
# container and INPUT rules (UFW, firewalld) never see them. DOCKER-USER is the chain
# Docker leaves for us; it runs before Docker's own accept rules. After DNAT the
# destination port is the container's, so rules match the original host port with
# conntrack (--ctorigdstport).
#
#   sudo deploy/firewall/siem-docker-user.sh             # apply (idempotent)
#   sudo deploy/firewall/siem-docker-user.sh --dry-run   # print the iptables commands only
#   sudo deploy/firewall/siem-docker-user.sh --remove
#
# Settings come from the environment or the repo's .env:
#   SIEM_EXT_IF          host interface facing the office network, e.g. eno1     (required)
#   OPNSENSE_SYSLOG_IP   the only source allowed to send syslog, e.g. 192.168.99.1 (required)
#   SIEM_ADMIN_NETS      comma list allowed to open the web UI, e.g. 192.168.99.0/24,10.8.0.0/24 (required)
#   SYSLOG_HOST_PORT (514), SYSLOG_TLS_HOST_PORT (6514), GRAYLOG_UI_PORT (9000)
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
if [ -f "$ROOT/.env" ]; then set -a; . "$ROOT/.env"; set +a; fi

CHAIN=SIEM-DOCKER
MODE=${1:-apply}
IPT=${IPTABLES:-iptables}

run() {
  if [ "$MODE" = "--dry-run" ]; then echo "$IPT $*"; else "$IPT" "$@"; fi
}

if [ "$MODE" = "--remove" ]; then
  while "$IPT" -C DOCKER-USER -i "${SIEM_EXT_IF:?}" -j "$CHAIN" 2>/dev/null; do
    "$IPT" -D DOCKER-USER -i "$SIEM_EXT_IF" -j "$CHAIN"
  done
  "$IPT" -F "$CHAIN" 2>/dev/null || true
  "$IPT" -X "$CHAIN" 2>/dev/null || true
  echo "removed $CHAIN"
  exit 0
fi

IF=${SIEM_EXT_IF:?set SIEM_EXT_IF (e.g. eno1)}
SYSLOG_SRC=${OPNSENSE_SYSLOG_IP:?set OPNSENSE_SYSLOG_IP (e.g. 192.168.99.1)}
ADMIN_NETS=${SIEM_ADMIN_NETS:?set SIEM_ADMIN_NETS (e.g. 192.168.99.0/24)}
SYSLOG_PORT=${SYSLOG_HOST_PORT:-514}
TLS_PORT=${SYSLOG_TLS_HOST_PORT:-6514}
UI_PORT=${GRAYLOG_UI_PORT:-9000}

if [ "$MODE" != "--dry-run" ] && ! "$IPT" -L DOCKER-USER -n >/dev/null 2>&1; then
  echo "DOCKER-USER chain not found: start Docker first" >&2
  exit 1
fi

# own chain, rebuilt from scratch on every run
if [ "$MODE" = "--dry-run" ] || ! "$IPT" -L "$CHAIN" -n >/dev/null 2>&1; then
  run -N "$CHAIN"
else
  run -F "$CHAIN"
fi
run -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

# syslog: OPNsense only
for spec in "udp $SYSLOG_PORT" "tcp $SYSLOG_PORT" "tcp $TLS_PORT"; do
  set -- $spec
  run -A "$CHAIN" -p "$1" -m conntrack --ctorigdstport "$2" --ctdir ORIGINAL -s "$SYSLOG_SRC" -j RETURN
  run -A "$CHAIN" -p "$1" -m conntrack --ctorigdstport "$2" --ctdir ORIGINAL -j DROP
done

# web UI / API: admin networks only
for net in $(echo "$ADMIN_NETS" | tr ',' ' '); do
  run -A "$CHAIN" -p tcp -m conntrack --ctorigdstport "$UI_PORT" --ctdir ORIGINAL -s "$net" -j RETURN
done
run -A "$CHAIN" -p tcp -m conntrack --ctorigdstport "$UI_PORT" --ctdir ORIGINAL -j DROP
run -A "$CHAIN" -j RETURN

# jump only for traffic arriving on the office-facing interface (container-to-container
# traffic on the Docker bridge is left alone)
if [ "$MODE" = "--dry-run" ] || ! "$IPT" -C DOCKER-USER -i "$IF" -j "$CHAIN" 2>/dev/null; then
  run -I DOCKER-USER 1 -i "$IF" -j "$CHAIN"
fi

[ "$MODE" = "--dry-run" ] || echo "applied $CHAIN on $IF: syslog from $SYSLOG_SRC, UI from $ADMIN_NETS"
