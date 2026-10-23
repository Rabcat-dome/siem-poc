#!/bin/sh
# Create a small private CA and a server certificate for the SIEM syslog-over-TLS
# input (NFR-05, ISO A.8.20 / A.8.24).
#
#   tools/gen_tls_certs.sh siem.example.local 10.10.10.5 [more SAN names/IPs ...]
#
# Output (repo root, git-ignored):
#   tls/ca.crt       CA certificate  -> import into OPNsense (System > Trust > Authorities)
#   tls/server.crt   server cert + CA chain, PEM          (Graylog tls_cert_file)
#   tls/server.key   server key, PKCS#8 PEM, unencrypted  (Graylog tls_key_file)
#   tls-ca/ca.key    CA private key. Kept OUT of tls/ on purpose: tls/ is mounted
#                    into the Graylog container. Store tls-ca/ offline after use.
#
# Env: DAYS_SERVER (default 825), DAYS_CA (default 3650), OUT_DIR (default <repo>/tls),
#      CA_DIR (default <repo>/tls-ca). Existing CA is reused; the server cert is re-issued.
set -eu

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <dns-name-or-ip> [<dns-name-or-ip> ...]   e.g. $0 siem.example.local 10.10.10.5" >&2
  exit 2
fi
command -v openssl >/dev/null 2>&1 || { echo "openssl not found" >&2; exit 1; }

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT_DIR=${OUT_DIR:-$ROOT/tls}
CA_DIR=${CA_DIR:-$ROOT/tls-ca}
DAYS_SERVER=${DAYS_SERVER:-825}
DAYS_CA=${DAYS_CA:-3650}
CN=$1

mkdir -p "$OUT_DIR" "$CA_DIR"
chmod 700 "$CA_DIR"
umask 077
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

# subjectAltName: IPs vs DNS names
SAN=""
for h in "$@"; do
  case $h in
    *[!0-9.]*) case $h in *:*) kind=IP ;; *) kind=DNS ;; esac ;;
    *) kind=IP ;;
  esac
  SAN="${SAN:+$SAN,}$kind:$h"
done

# --- CA (reused when present) ---
if [ -f "$CA_DIR/ca.key" ] && [ -f "$OUT_DIR/ca.crt" ]; then
  echo "reusing existing CA ($OUT_DIR/ca.crt)"
else
  # CA extensions spelled out: strict clients (Python 3.13+, OpenSSL 3 with X509_STRICT)
  # reject a CA without key identifiers or keyCertSign usage
  cat > "$WORK/ca.cnf" <<CA
[req]
distinguished_name = dn
x509_extensions = v3_ca
[dn]
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
CA
  openssl genrsa -out "$CA_DIR/ca.key" 4096 2>/dev/null
  openssl req -x509 -new -key "$CA_DIR/ca.key" -sha256 -days "$DAYS_CA" -config "$WORK/ca.cnf" \
    -subj "/O=SIEM POC/CN=SIEM POC Private CA" -out "$OUT_DIR/ca.crt"
  echo "created CA: $OUT_DIR/ca.crt"
fi

# --- server key (PKCS#8, unencrypted) + CSR ---
openssl genrsa -out "$WORK/server.rsa" 2048 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$WORK/server.rsa" -out "$OUT_DIR/server.key"
openssl req -new -key "$OUT_DIR/server.key" -subj "/O=SIEM POC/CN=$CN" -out "$WORK/server.csr"

cat > "$WORK/ext.cnf" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$SAN
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT
openssl x509 -req -in "$WORK/server.csr" -CA "$OUT_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" \
  -CAcreateserial -CAserial "$CA_DIR/ca.srl" -days "$DAYS_SERVER" -sha256 \
  -extfile "$WORK/ext.cnf" -out "$WORK/server.pem" 2>/dev/null
cat "$WORK/server.pem" "$OUT_DIR/ca.crt" > "$OUT_DIR/server.crt"

# Graylog runs as uid 1100 in the container and reads these through a read-only
# bind mount, so they must be world-readable (the key's protection is the host
# directory permissions / the SIEM host itself). CA key stays 600 in $CA_DIR.
chmod 755 "$OUT_DIR"
chmod 644 "$OUT_DIR/ca.crt" "$OUT_DIR/server.crt" "$OUT_DIR/server.key"
chmod 600 "$CA_DIR/ca.key"

openssl verify -CAfile "$OUT_DIR/ca.crt" "$WORK/server.pem" >/dev/null
echo "server cert: $OUT_DIR/server.crt  (SAN: $SAN)"
openssl x509 -in "$WORK/server.pem" -noout -enddate | sed 's/^/  /'
echo "server key : $OUT_DIR/server.key  (PKCS#8, unencrypted)"
echo "CA key     : $CA_DIR/ca.key  (NOT mounted into containers; move offline)"

cat <<NEXT

Next steps
  SIEM side
    1. docker compose up -d graylog      # mounts ./tls, publishes 6514/tcp
    2. docker compose run --rm provisioner   # creates input "OPNsense Syslog TLS 6514"
  OPNsense side
    1. System > Trust > Authorities > Add: Method "Import an existing Certificate
       Authority", paste the contents of tls/ca.crt (certificate only, NO private key).
    2. System > Settings > Logging > Remote > Add:
         Transport  TLS(4)  (TLS(6) for IPv6)
         Hostname   $CN      (must match a SAN above; use the IP if DNS is not available)
         Port       6514
         Applications / Levels: as required (e.g. filter, dhcpd, audit, system)
         Certificate: leave empty (no client auth)
    3. Save, Apply. Check System > Log Files > General for TLS handshake errors.
       (Trust is verified against the imported CA; if it fails, check the SAN and the clock.)
NEXT
