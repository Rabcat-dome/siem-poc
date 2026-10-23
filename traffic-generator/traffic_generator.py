#!/usr/bin/env python3
"""Real traffic through a *test* OPNsense, so the SIEM sees logs the firewall wrote itself.

Run it on a machine in the LAN behind the test OPNsense (not the production
firewall). It only does what an ordinary user or a misconfigured laptop does:

  baseline          DNS lookups through OPNsense + HTTPS requests to common sites,
                    including allowed-but-monitored categories (social, streaming)
  blocked_category  DNS lookups of the test domains that Unbound's blocklist should
                    sinkhole (gambling, adult, drugs, p2p - all *.example)   -> WEB-01
  dns_bypass        try DoT (853), plain DNS to an outside resolver (53) and a DoH
                    resolver (443); the firewall should drop all of them    -> WEB-02

Each policy check prints whether OPNsense actually enforced the control, so the
run doubles as evidence that web filtering works (ISO A.8.23).

  python traffic_generator.py --dns 192.168.1.1                 # continuous, every 5 s
  python traffic_generator.py --dns 192.168.1.1 --play all      # one pass of every check, then exit
"""
import argparse
import os
import random
import socket
import ssl
import struct
import sys
import time
import urllib.request

NORMAL_SITES = ["www.google.com", "www.microsoft.com", "github.com", "www.bot.or.th", "line.me"]
MONITORED_SITES = ["www.facebook.com", "www.youtube.com", "www.tiktok.com", "drive.google.com"]
# must also be in graylog/lookup/web_categories.csv (policy=block) and in Unbound's custom blocklist
BLOCKED_DOMAINS = ["thaicasino-bet.example", "www.slot-888.example", "adult-videos.example",
                   "drugs-shop.example", "torrent-tracker.example", "piratebay-mirror.example"]
OUTSIDE_RESOLVERS = {"dot": ["1.1.1.1", "8.8.8.8"], "dns": ["8.8.8.8", "1.1.1.1"], "doh": ["9.9.9.9"]}
SINKHOLE = {"0.0.0.0", "127.0.0.1", "::"}
TIMEOUT = 3


# --- minimal DNS client (stdlib only) ----------------------------------------

def dns_query(server, name, port=53, timeout=TIMEOUT):
    """Return (rcode, first A record or None). Raises socket.timeout if nothing answers."""
    qid = random.randint(0, 0xFFFF)
    question = b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\0"
    packet = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + question + struct.pack(">HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, port))
        data, _ = s.recvfrom(4096)
    rcode, ancount = data[3] & 0x0F, struct.unpack(">H", data[6:8])[0]
    pos = 12 + len(question) + 4
    for _ in range(ancount):
        pos = _skip_name(data, pos)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == 1 and rdlen == 4:
            return rcode, socket.inet_ntoa(data[pos:pos + 4])
        pos += rdlen
    return rcode, None


def _skip_name(data, pos):
    while data[pos]:
        if data[pos] & 0xC0 == 0xC0:  # compression pointer ends the name
            return pos + 2
        pos += data[pos] + 1
    return pos + 1


def tcp_reachable(ip, port, timeout=TIMEOUT):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


# --- activities --------------------------------------------------------------

def baseline(dns):
    for site in random.sample(NORMAL_SITES + MONITORED_SITES, 3):
        try:
            dns_query(dns, site)
            req = urllib.request.Request(f"https://{site}/", method="HEAD", headers={"User-Agent": "siem-poc-traffic"})
            with urllib.request.urlopen(req, timeout=5, context=ssl.create_default_context()) as r:
                status = r.status
        except Exception as e:  # noqa: BLE001 - any failure is just logged; this is background noise
            status = type(e).__name__
        print(f"  browse  {site:<22} -> {status}")


def blocked_category(dns):
    """WEB-01 needs >= 10 queries per host per hour; every one should come back sinkholed.

    Only the sinkhole address counts as enforced: *.example never exists, so NXDOMAIN
    would "pass" even with no blocklist at all (keep Unbound's blocklist on 0.0.0.0).
    """
    results = []
    for _ in range(random.randint(10, 13)):
        domain = random.choice(BLOCKED_DOMAINS)
        try:
            rcode, ip = dns_query(dns, domain)
            enforced = ip in SINKHOLE
            detail = f"sinkholed to {ip}" if enforced else f"rcode={rcode} ip={ip} (not on the blocklist?)"
        except socket.timeout:
            enforced, detail = False, f"no answer from {dns} (wrong --dns?)"
        results.append(("DNS blocklist", domain, enforced, detail))
    return results


def dns_bypass(_dns):
    results = []
    for ip in OUTSIDE_RESOLVERS["dot"]:
        ok = tcp_reachable(ip, 853)
        results.append(("Block DoT 853", f"{ip}:853", not ok, "connected" if ok else "blocked/timeout"))
    for ip in OUTSIDE_RESOLVERS["dns"]:
        try:
            dns_query(ip, "www.google.com")
            results.append(("Block outside DNS 53", f"{ip}:53", False, "answered"))
        except OSError:
            results.append(("Block outside DNS 53", f"{ip}:53", True, "blocked/timeout"))
    for ip in OUTSIDE_RESOLVERS["doh"]:
        ok = tcp_reachable(ip, 443)
        results.append(("Block DoH resolver", f"{ip}:443", not ok, "connected" if ok else "blocked/timeout"))
    return results


CHECKS = {"blocked_category": blocked_category, "dns_bypass": dns_bypass}


def report(results):
    for control, target, enforced, detail in results:
        print(f"  {'PASS' if enforced else 'FAIL'}  {control:<22} {target:<26} {detail}")
    return all(r[2] for r in results)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dns", default=os.getenv("OPNSENSE_DNS"), required=not os.getenv("OPNSENSE_DNS"),
                        help="OPNsense LAN address (Unbound)")
    parser.add_argument("--interval", type=float, default=float(os.getenv("INTERVAL_SECONDS", "5")))
    parser.add_argument("--rate", type=float, default=float(os.getenv("SCENARIO_RATE", "0.1")),
                        help="chance per tick of running a policy check")
    parser.add_argument("--play", nargs="+", metavar="CHECK", help=f"run once and exit: all or {', '.join(CHECKS)}")
    args = parser.parse_args()

    if args.play:
        names = list(CHECKS) if args.play == ["all"] else args.play
        unknown = [n for n in names if n not in CHECKS]
        if unknown:
            sys.exit(f"unknown check(s) {unknown}; choose from: all, {', '.join(CHECKS)}")
        passed = True
        for name in names:
            print(f"{name}:")
            passed &= report(CHECKS[name](args.dns))
        print("all controls enforced" if passed else "SOME CONTROLS ARE NOT ENFORCED - check OPNsense rules/blocklist")
        sys.exit(0 if passed else 1)

    print(f"traffic generator via OPNsense {args.dns}, every {args.interval}s (policy check rate {args.rate})")
    tick = 0
    while True:
        tick += 1
        print(f"tick {tick}")
        baseline(args.dns)
        if random.random() < args.rate:
            name = random.choice(list(CHECKS))
            print(f"  {name}:")
            report(CHECKS[name](args.dns))
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
