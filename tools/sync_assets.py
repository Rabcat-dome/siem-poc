#!/usr/bin/env python3
"""Build graylog/lookup/assets.csv from OPNsense DHCP static mappings (decision Q5, no AD).

Identity lives in the static mapping's description, one convention for every backend:

  owner=somchai.k;dept=Finance;crit=medium

Missing keys give an empty cell, free text without "=" is ignored, crit must be
low|medium|high|critical (anything else is dropped with a warning). Hosts that are
not DHCP-mapped (servers, firewall interfaces) live in assets_static.csv, which is
merged in and wins on an IP conflict. The result is written atomically
(temp file + rename) and a diff against the old file is printed.

Backends (--backend):
  kea         POST /api/kea/dhcpv4/search_reservation        (Kea DHCPv4)
  dnsmasq     POST /api/dnsmasq/settings/search_host         (dnsmasq, OPNsense 25.x)
  config-xml  --from-config-xml config.xml                   (ISC dhcpd: it has no API)

  python sync_assets.py --backend kea --insecure --dry-run
  python sync_assets.py --backend dnsmasq
  python sync_assets.py --from-config-xml config-OPNsense.xml

Env: OPNSENSE_URL (https://192.168.99.1), OPNSENSE_KEY, OPNSENSE_SECRET
Exit code is 1 on any error and the old assets.csv is left alone.
"""
import argparse
import base64
import csv
import ipaddress
import json
import os
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

HEADER = ["ip", "hostname", "owner", "department", "criticality"]
CRIT = {"low", "medium", "high", "critical"}
LOOKUP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "graylog", "lookup")


def warn(msg):
    print(f"warning: {msg}", file=sys.stderr)


def parse_descr(descr):
    """'owner=a;dept=b;crit=high' -> (owner, dept, crit); unknown keys and free text are ignored."""
    kv = {}
    for part in (descr or "").split(";"):
        key, eq, value = part.partition("=")
        if eq:
            kv[key.strip().lower()] = value.strip()
    crit = kv.get("crit", "").lower()
    if crit and crit not in CRIT:
        warn(f"unknown crit={crit!r} ignored")
        crit = ""
    return kv.get("owner", ""), kv.get("dept", ""), crit


def make_row(ip, hostname, descr):
    try:
        ip = str(ipaddress.IPv4Address(str(ip).strip()))
    except ValueError:
        warn(f"skipping mapping with bad IPv4 address {ip!r}")
        return None
    owner, dept, crit = parse_descr(descr)
    return [ip, (hostname or "").strip(), owner, dept, crit]


# ---- OPNsense API ----------------------------------------------------------

def api_post(args, path, body):
    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    token = base64.b64encode(f"{os.environ['OPNSENSE_KEY']}:{os.environ['OPNSENSE_SECRET']}".encode()).decode()
    req = urllib.request.Request(args.url.rstrip("/") + path, method="POST", data=json.dumps(body).encode(),
                                 headers={"Authorization": f"Basic {token}", "Content-Type": "application/json",
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=args.timeout, context=ctx) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        sys.exit(f"{path}: HTTP {e.code} {e.reason}")
    except (urllib.error.URLError, OSError, ValueError) as e:
        sys.exit(f"{path}: {e}")


def grid(args, path):
    """All rows of an OPNsense search grid (rowCount -1 = no paging)."""
    data = api_post(args, path, {"current": 1, "rowCount": -1, "searchPhrase": ""})
    rows = data.get("rows")
    if rows is None:
        sys.exit(f"{path}: no 'rows' in response")
    return rows


def from_kea(args):
    rows = []
    for r in grid(args, "/api/kea/dhcpv4/search_reservation"):
        row = make_row(r.get("ip_address"), r.get("hostname"), r.get("description"))
        if row:
            rows.append(row)
    return rows


def from_dnsmasq(args):
    rows = []
    for r in grid(args, "/api/dnsmasq/settings/search_host"):
        if r.get("ignore") in ("1", 1, True):
            continue
        # ip can hold several addresses (comma separated); take the first IPv4
        ips = [i.strip() for i in str(r.get("ip") or "").split(",") if "." in i]
        if not ips:
            continue  # IPv6-only or empty (e.g. a MAC-only host entry)
        row = make_row(ips[0], r.get("host"), r.get("descr"))
        if row:
            rows.append(row)
    return rows


def from_config_xml(args):
    try:
        root = ET.parse(args.from_config_xml).getroot()
    except (OSError, ET.ParseError) as e:
        sys.exit(f"{args.from_config_xml}: {e}")
    rows = []
    # <opnsense><dhcpd><lan><staticmap><ipaddr/><hostname/><descr/>...
    for iface in root.findall("./dhcpd/*"):
        for sm in iface.findall("staticmap"):
            row = make_row(sm.findtext("ipaddr"), sm.findtext("hostname"), sm.findtext("descr"))
            if row:
                rows.append(row)
    return rows


# ---- CSV -------------------------------------------------------------------

def read_csv(path, required=True):
    if not os.path.exists(path):
        if required:
            sys.exit(f"not found: {path}")
        return []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        head = next(reader, None)
        if head != HEADER:
            sys.exit(f"{path}: header must be {HEADER}, got {head}")
        return [r for r in reader if r]


def write_atomic(path, rows):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".assets-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, quoting=csv.QUOTE_ALL, lineterminator="\n")
            w.writerow(HEADER)
            w.writerows(rows)
        os.chmod(tmp, 0o644)  # mkstemp creates 0600; Graylog's container must read it
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def merge(mapped, static):
    by_ip = {}
    for row in mapped:
        if row[0] in by_ip:
            warn(f"duplicate DHCP mapping for {row[0]}: {by_ip[row[0]][1]} replaced by {row[1]}")
        by_ip[row[0]] = row
    for row in static:
        if row[0] in by_ip and by_ip[row[0]] != row:
            print(f"note: {row[0]} in assets_static.csv overrides the DHCP mapping")
        by_ip[row[0]] = row
    return sorted(by_ip.values(), key=lambda r: ipaddress.IPv4Address(r[0]))


def print_diff(old, new):
    o, n = {r[0]: r for r in old}, {r[0]: r for r in new}
    added = sorted(set(n) - set(o), key=ipaddress.IPv4Address)
    removed = sorted(set(o) - set(n), key=ipaddress.IPv4Address)
    changed = sorted((i for i in set(o) & set(n) if o[i] != n[i]), key=ipaddress.IPv4Address)
    for i in added:
        print(f"+ {','.join(n[i])}")
    for i in removed:
        print(f"- {','.join(o[i])}")
    for i in changed:
        print(f"~ {i}: {','.join(o[i][1:])} -> {','.join(n[i][1:])}")
    print(f"assets: {len(new)} rows ({len(added)} added, {len(removed)} removed, {len(changed)} changed)")
    return bool(added or removed or changed)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--backend", choices=["kea", "dnsmasq", "config-xml"], default="kea")
    p.add_argument("--from-config-xml", metavar="FILE", help="config.xml backup (implies --backend config-xml)")
    p.add_argument("--url", default=os.getenv("OPNSENSE_URL", ""), help="default $OPNSENSE_URL")
    p.add_argument("--insecure", action="store_true", help="accept a self-signed OPNsense certificate")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--static", default=os.path.join(LOOKUP, "assets_static.csv"))
    p.add_argument("--out", default=os.path.join(LOOKUP, "assets.csv"))
    p.add_argument("--dry-run", action="store_true", help="print the diff, do not write")
    args = p.parse_args()

    if args.from_config_xml:
        args.backend = "config-xml"
    if args.backend == "config-xml":
        if not args.from_config_xml:
            sys.exit("--backend config-xml needs --from-config-xml FILE")
        mapped = from_config_xml(args)
    else:
        missing = [v for v in ("OPNSENSE_KEY", "OPNSENSE_SECRET") if not os.getenv(v)]
        if missing or not args.url:
            sys.exit("set OPNSENSE_URL, OPNSENSE_KEY and OPNSENSE_SECRET (or use --from-config-xml)")
        mapped = from_kea(args) if args.backend == "kea" else from_dnsmasq(args)
    if not mapped:
        warn("backend returned no DHCP mappings; only assets_static.csv will remain")

    new = merge(mapped, read_csv(args.static, required=False))
    old = read_csv(args.out, required=False)
    changed = print_diff(old, new)
    if args.dry_run:
        print("dry run: nothing written")
    elif changed or not os.path.exists(args.out):
        write_atomic(args.out, new)
        print(f"wrote {args.out}")
    else:
        print("no change")


if __name__ == "__main__":
    main()
