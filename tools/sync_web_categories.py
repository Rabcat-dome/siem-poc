#!/usr/bin/env python3
"""Build graylog/lookup/web_categories.csv from web_categories_sources.json (decision Q13).

The JSON maps category -> policy (block|monitor) -> list of sources:
  {"inline": ["a.example", ...]}   domains written in the JSON itself
  {"file": "lists/gambling.txt"}   local file, path relative to the JSON
  {"url": "https://.../hosts"}     plain domain list or hosts format (0.0.0.0 domain)
Every source may carry "enabled": false and "max_domains": N. Optionally the domains of the
OPNsense Unbound custom blocklist are added ("opnsense_unbound_blocklist" in the JSON, or --opnsense).

Normalising: lowercase, strip comments, hosts prefix (0.0.0.0 / 127.0.0.1), "*." and trailing dots.
Dedupe: block sources are read before monitor ones, so block beats monitor; otherwise the first
category in the JSON wins. A source with more than max_domains domains is cut with a warning
(Graylog keeps the whole CSV in memory). The CSV is written atomically.

  python sync_web_categories.py --dry-run
  python sync_web_categories.py --opnsense --insecure
  python sync_web_categories.py --offline        # skip URL sources, no network at all

Env (only for --opnsense): OPNSENSE_URL, OPNSENSE_KEY, OPNSENSE_SECRET
Exit code is 1 on any error and the old web_categories.csv is left alone.
"""
import argparse
import base64
import csv
import json
import os
import re
import ssl
import sys
import tempfile
import urllib.error
import urllib.request

HEADER = ["domain", "category", "policy"]
POLICIES = ("block", "monitor")  # processing order: block first, so block beats monitor
LOOKUP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "graylog", "lookup")
DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost"}
MAX_BYTES = 100 * 1024 * 1024


def warn(msg):
    print(f"warning: {msg}", file=sys.stderr)


def normalise(line):
    """One list line -> domain or None."""
    line = line.split("#", 1)[0].strip().lower()
    if not line:
        return None
    parts = line.split()
    if len(parts) > 1 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1", "::"):
        line = parts[1]  # hosts format
    else:
        line = parts[0]
    line = line.removeprefix("*.").rstrip(".")
    if line in SKIP or not DOMAIN.match(line):
        return None
    return line


def parse_lines(lines):
    return [d for d in (normalise(x) for x in lines) if d]


def http_get(url, headers=None, ctx=None, timeout=60, data=None):
    req = urllib.request.Request(url, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(MAX_BYTES + 1)
    except (urllib.error.URLError, OSError) as e:
        sys.exit(f"{url}: {e}")


def read_source(src, base_dir, args):
    """Raw domains of one source (not yet capped); None when skipped."""
    if "inline" in src:
        return parse_lines(src["inline"])
    if "file" in src:
        path = os.path.join(base_dir, src["file"])
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return parse_lines(f)
        except OSError as e:
            sys.exit(f"{path}: {e}")
    if "url" in src:
        if args.offline:
            warn(f"--offline: skipped {src['url']}")
            return None
        body = http_get(src["url"], timeout=args.timeout)
        if len(body) > MAX_BYTES:
            sys.exit(f"{src['url']}: larger than {MAX_BYTES // 1024 // 1024} MB")
        return parse_lines(body.decode("utf-8", errors="replace").splitlines())
    sys.exit(f"source needs inline, file or url: {json.dumps(src)[:80]}")


# ---- OPNsense Unbound custom blocklist --------------------------------------

def csv_items(value):
    """CSVListField as returned by the API: 'a,b' string or {'a': {'value':..,'selected':1}, ...}."""
    if isinstance(value, dict):
        return [k for k, v in value.items() if not isinstance(v, dict) or v.get("selected", 1)]
    return [x for x in str(value or "").replace("\n", ",").split(",") if x.strip()]


def opnsense_blocklist(args):
    """Custom blocklist domains from Unbound DNSBL (blocklists + wildcards fields)."""
    for var in ("OPNSENSE_URL", "OPNSENSE_KEY", "OPNSENSE_SECRET"):
        if not os.getenv(var):
            sys.exit(f"--opnsense needs {var}")
    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    token = base64.b64encode(f"{os.environ['OPNSENSE_KEY']}:{os.environ['OPNSENSE_SECRET']}".encode()).decode()
    hdr = {"Authorization": f"Basic {token}", "Accept": "application/json", "Content-Type": "application/json"}
    base = os.environ["OPNSENSE_URL"].rstrip("/")
    items = []
    # newer releases: dnsbl entries are an ArrayField, listed by search_dnsbl
    try:
        body = json.dumps({"current": 1, "rowCount": -1, "searchPhrase": ""}).encode()
        rows = json.loads(http_get_soft(base + "/api/unbound/settings/search_dnsbl", hdr, ctx, args.timeout, body))["rows"]
        for r in rows:
            if r.get("enabled", "1") in ("1", 1, True):
                items += csv_items(r.get("blocklists")) + csv_items(r.get("wildcards"))
    except (ValueError, KeyError, LookupError):
        rows = None
    if not rows:
        # older releases: unbound.dnsbl.{blocklists,wildcards} inside settings/get
        data = json.loads(http_get(base + "/api/unbound/settings/get", hdr, ctx, args.timeout))
        dnsbl = data.get("unbound", {}).get("dnsbl", {})
        if "blocklists" not in dnsbl:
            warn("no blocklists field in unbound dnsbl settings; custom blocklist is empty")
        items = csv_items(dnsbl.get("blocklists")) + csv_items(dnsbl.get("wildcards"))
    return parse_lines(items)


def http_get_soft(url, hdr, ctx, timeout, data):
    """POST that returns '' on HTTP errors instead of exiting (endpoint may not exist)."""
    req = urllib.request.Request(url, headers=hdr, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read()
    except urllib.error.HTTPError:
        return b"{}"
    except (urllib.error.URLError, OSError) as e:
        sys.exit(f"{url}: {e}")


# ---- build -----------------------------------------------------------------

def sources_in_order(cfg, args):
    """Yield (category, policy, label, raw domains, cap) block-first."""
    default_cap = int(cfg.get("max_domains_per_source", 50000))
    cats = {k: v for k, v in cfg.get("categories", {}).items() if not k.startswith("_")}
    blocklist = cfg.get("opnsense_unbound_blocklist", {})
    use_opn = args.opnsense or blocklist.get("enabled", False)
    for policy in POLICIES:
        for category, by_policy in cats.items():
            for src in by_policy.get(policy, []):
                if not src.get("enabled", True):
                    continue
                domains = read_source(src, args.base_dir, args)
                if domains is not None:
                    label = src.get("url") or src.get("file") or "inline"
                    yield category, policy, label, domains, int(src.get("max_domains", default_cap))
        if use_opn and blocklist.get("policy", "block") == policy:
            yield (blocklist.get("category", "custom-block"), policy, "opnsense unbound blocklist",
                   opnsense_blocklist(args), int(blocklist.get("max_domains", default_cap)))


def build(cfg, args):
    seen, rows, stats = {}, [], {}
    for category, policy, label, domains, cap in sources_in_order(cfg, args):
        if len(domains) > cap:
            warn(f"{category}/{policy}: {label} has {len(domains)} domains, keeping the first {cap}")
            domains = domains[:cap]
        st = stats.setdefault((category, policy), {"added": 0, "dup": 0})
        for d in domains:
            if d in seen:
                st["dup"] += 1
                if seen[d][1] != policy or seen[d][0] != category:
                    print(f"note: {d} already in {seen[d][0]}/{seen[d][1]}, ignored for {category}/{policy}")
            else:
                seen[d] = (category, policy)
                rows.append([d, category, policy])
                st["added"] += 1
    return rows, stats


def read_old(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.reader(f))[1:]


def write_atomic(path, rows):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".web-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, quoting=csv.QUOTE_ALL, lineterminator="\n")
            w.writerow(HEADER)
            w.writerows(rows)
        os.chmod(tmp, 0o644)  # Graylog's container must be able to read it
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", default=os.path.join(LOOKUP, "web_categories_sources.json"))
    p.add_argument("--out", default=os.path.join(LOOKUP, "web_categories.csv"))
    p.add_argument("--opnsense", action="store_true", help="add the Unbound custom blocklist even if disabled in the JSON")
    p.add_argument("--insecure", action="store_true", help="accept a self-signed OPNsense certificate")
    p.add_argument("--offline", action="store_true", help="skip URL sources")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--dry-run", action="store_true", help="print the summary, do not write")
    args = p.parse_args()

    try:
        with open(args.config, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        sys.exit(f"{args.config}: {e}")
    args.base_dir = os.path.dirname(os.path.abspath(args.config))

    rows, stats = build(cfg, args)
    if not rows:
        sys.exit("no domains produced; refusing to write an empty file")
    for (category, policy), st in stats.items():
        print(f"{policy:8} {category:16} {st['added']:6} domains ({st['dup']} duplicates dropped)")

    old = {r[0]: r for r in read_old(args.out)}
    new = {r[0]: r for r in rows}
    print(f"web_categories: {len(rows)} rows ({len(set(new) - set(old))} added, "
          f"{len(set(old) - set(new))} removed, {sum(1 for d in set(old) & set(new) if old[d] != new[d])} changed)")
    if args.dry_run:
        print("dry run: nothing written")
        return
    write_atomic(args.out, rows)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
