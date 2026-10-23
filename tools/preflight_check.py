#!/usr/bin/env python3
"""Pre-go-live check of a .env file for the SIEM stack (ISO A.8.9, A.8.5, A.8.24).

  python tools/preflight_check.py [--env .env] [--tls-dir tls]

Prints PASS / WARN / FAIL lines; exit code 1 when any FAIL (so it can gate a
deploy script). Values missing from the file fall back to the docker-compose
defaults, which are POC values and therefore fail.
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

DEFAULT_SECRET = "poc-only-change-me-0123456789abcdef0123456789abcdef"
EXAMPLE_SECRET = "change-me-0123456789abcdef0123456789abcdef"
ADMIN_SHA = hashlib.sha256(b"admin").hexdigest()
MIN_SECRET = 32          # Graylog needs 16; we want 32+ (openssl rand -hex 32 gives 64)
CERT_WARN_DAYS = 30

results = []


def report(level, msg):
    results.append(level)
    print(f"{level:<4}  {msg}")


def read_env(path):
    env = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            env[k.strip()] = v
    return env


def check_secrets(env):
    sha = env.get("GRAYLOG_ROOT_PASSWORD_SHA2", ADMIN_SHA).lower()
    if sha == ADMIN_SHA:
        report("FAIL", "GRAYLOG_ROOT_PASSWORD_SHA2 is the hash of 'admin'")
    elif len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        report("FAIL", "GRAYLOG_ROOT_PASSWORD_SHA2 is not a SHA-256 hex digest")
    else:
        report("PASS", "root password hash is not the default")

    if env.get("GRAYLOG_ADMIN_PASSWORD", "admin") == "admin":
        report("FAIL", "GRAYLOG_ADMIN_PASSWORD is 'admin' (provisioner would use the default password)")
    elif hashlib.sha256(env["GRAYLOG_ADMIN_PASSWORD"].encode()).hexdigest() != sha:
        report("FAIL", "GRAYLOG_ADMIN_PASSWORD does not match GRAYLOG_ROOT_PASSWORD_SHA2 (provisioner login would fail)")
    else:
        report("PASS", "GRAYLOG_ADMIN_PASSWORD matches the root hash")

    secret = env.get("GRAYLOG_PASSWORD_SECRET", DEFAULT_SECRET)
    if secret in (DEFAULT_SECRET, EXAMPLE_SECRET):
        report("FAIL", "GRAYLOG_PASSWORD_SECRET is the shipped default")
    elif len(secret) < MIN_SECRET:
        report("FAIL" if len(secret) < 16 else "WARN",
               f"GRAYLOG_PASSWORD_SECRET is only {len(secret)} chars (use: openssl rand -hex 32)")
    else:
        report("PASS", f"GRAYLOG_PASSWORD_SECRET set ({len(secret)} chars)")

    for key, who in (("IT_ANALYST_PASSWORD", "it-analyst"), ("LOG_ADMIN_PASSWORD", "log-admin")):
        v = env.get(key, "")
        if not v:
            report("FAIL", f"{key} is empty: RBAC user {who} would not be created")
        elif len(v) < 12:
            report("WARN", f"{key} is shorter than 12 chars")
        else:
            report("PASS", f"{key} set")

    if env.get("REPORT_USER", "admin") == "admin":
        report("FAIL", "REPORT_USER is still 'admin' (use the read-limited it-analyst account)")
    else:
        report("PASS", f"REPORT_USER is {env['REPORT_USER']}")
    if env.get("REPORT_PASSWORD", "admin") == "admin":
        report("FAIL", "REPORT_PASSWORD is 'admin'")


def cert_end(path):
    """notAfter as aware datetime via `openssl x509 -enddate`, or None if openssl is unavailable/unreadable."""
    if not shutil.which("openssl"):
        return None
    p = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-enddate"], capture_output=True, text=True)
    if p.returncode != 0 or "=" not in p.stdout:
        return None
    try:
        return datetime.strptime(p.stdout.strip().split("=", 1)[1], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def check_tls(tls_dir):
    cert, key = os.path.join(tls_dir, "server.crt"), os.path.join(tls_dir, "server.key")
    missing = [os.path.basename(p) for p in (cert, key) if not os.path.isfile(p)]
    if missing:
        report("FAIL", f"TLS files missing in {tls_dir}: {', '.join(missing)} (run tools/gen_tls_certs.sh)")
        return
    report("PASS", f"TLS cert and key present in {tls_dir}")
    end = cert_end(cert)
    if end is None:
        report("WARN", "could not read certificate expiry (openssl missing or unreadable cert)")
        return
    left = end - datetime.now(timezone.utc)
    if left <= timedelta(0):
        report("FAIL", f"TLS certificate expired on {end:%Y-%m-%d}")
    elif left < timedelta(days=CERT_WARN_DAYS):
        report("FAIL", f"TLS certificate expires in {left.days} days ({end:%Y-%m-%d}), renew now")
    else:
        report("PASS", f"TLS certificate valid for {left.days} more days (until {end:%Y-%m-%d})")


def valid_port(v):
    return v.isdigit() and 1 <= int(v) <= 65535


def check_ports(env, prod=False):
    syslog = env.get("SYSLOG_HOST_PORT", "1514")
    tls = env.get("SYSLOG_TLS_HOST_PORT", "6514")
    for name, v in (("SYSLOG_HOST_PORT", syslog), ("SYSLOG_TLS_HOST_PORT", tls)):
        if not valid_port(v):
            report("FAIL", f"{name}={v!r} is not a valid port")
    if valid_port(syslog):
        if syslog == "514":
            report("PASS", "syslog UDP/TCP published on the standard port 514")
        else:
            report("WARN", f"SYSLOG_HOST_PORT={syslog} (POC value; production normally uses 514)")
    if valid_port(tls):
        if tls == "6514":
            report("PASS", "syslog TLS published on 6514")
        else:
            report("WARN", f"SYSLOG_TLS_HOST_PORT={tls} (standard is 6514)")
    if valid_port(syslog) and syslog == tls:
        report("FAIL", "SYSLOG_HOST_PORT and SYSLOG_TLS_HOST_PORT are the same")

    if prod:  # docker-compose.prod.yml binds the UI to SIEM_HOST_IP, checked in check_prod()
        return
    ui = env.get("GRAYLOG_UI_BIND", "127.0.0.1:9000")
    host = ui.rsplit(":", 1)[0] if ":" in ui else ""
    if not host or host in ("0.0.0.0", "::", "[::]", "*"):
        report("FAIL", f"GRAYLOG_UI_BIND={ui!r} exposes the web UI on every interface (bind the Management VLAN IP)")
    elif host in ("127.0.0.1", "localhost", "[::1]"):
        report("WARN", f"GRAYLOG_UI_BIND={ui} is loopback only: fine for a POC, unreachable from the Management VLAN")
    else:
        report("PASS", f"web UI bound to {ui}")


PROD_REQUIRED = ("SIEM_FQDN", "SIEM_HOST_IP", "SIEM_EXT_IF", "OPNSENSE_SYSLOG_IP", "SIEM_ADMIN_NETS",
                 "SMTP_HOST", "ALERT_FROM", "ALERT_EMAIL_TO", "REPORT_EMAIL_TO", "BACKUP_DIR")


def cert_names(path):
    """subjectAltName entries of a PEM certificate, e.g. {'DNS:graylog', 'IP Address:192.168.99.20'}."""
    try:
        out = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-text"],
                             capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    names, grab = set(), False
    for line in out.splitlines():
        if "Subject Alternative Name" in line:
            grab = True
            continue
        if grab:
            names = {n.strip() for n in line.split(",")}
            break
    return names


def check_prod(env, tls_dir):
    """docker-compose.prod.yml, deploy/ firewall, jobs and backup."""
    for name in PROD_REQUIRED:
        if not env.get(name):
            report("FAIL", f"{name} is empty (required by docker-compose.prod.yml / deploy/)")
    ip = env.get("SIEM_HOST_IP", "")
    if ip in ("0.0.0.0", "127.0.0.1", "::", "::1"):
        report("FAIL", f"SIEM_HOST_IP={ip} must be the host's Management VLAN address")
    names = cert_names(os.path.join(tls_dir, "server.crt"))
    if names is not None:
        for want in (f"IP Address:{ip}" if ip else None, f"DNS:{env.get('SIEM_FQDN', '')}", "DNS:graylog"):
            if want and not want.endswith(":") and want not in names:
                report("FAIL", f"server certificate has no {want}: re-run tools/gen_tls_certs.sh with it")
    if not env.get("BACKUP_PASSPHRASE"):
        report("WARN", "BACKUP_PASSPHRASE is empty: config backups (with .env secrets and the TLS key) stay unencrypted")
    if not env.get("OPNSENSE_URL"):
        report("WARN", "OPNSENSE_URL is empty: sync-assets and the OPNsense config backup will not run")
    if not (env.get("ARCHIVE_DIR") and env.get("MANIFEST_DIR")):
        report("WARN", "ARCHIVE_DIR / MANIFEST_DIR not set: the SHA-256 manifest jobs will fail")
    if env.get("WEBHOOK_URL"):
        report("WARN", "WEBHOOK_URL is set although Q4 decided e-mail only")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    ap.add_argument("--env", default=os.path.join(root, ".env"), help="path to the .env file (default: repo .env)")
    ap.add_argument("--tls-dir", default=os.path.join(root, "tls"), help="directory with server.crt / server.key")
    ap.add_argument("--prod", action="store_true", help="also check the docker-compose.prod.yml / deploy/ settings")
    args = ap.parse_args()
    if not os.path.isfile(args.env):
        print(f"FAIL  {args.env} not found (copy .env.example to .env first)")
        return 1
    env = read_env(args.env)
    print(f"preflight: {os.path.abspath(args.env)}")
    check_secrets(env)
    check_tls(args.tls_dir)
    check_ports(env, prod=args.prod)
    if args.prod:
        check_prod(env, args.tls_dir)
    fails, warns = results.count("FAIL"), results.count("WARN")
    print(f"\n{results.count('PASS')} pass, {warns} warn, {fails} fail")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
