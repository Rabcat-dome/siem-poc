#!/usr/bin/env python3
"""Disk usage check of the SIEM host (OPS-03; replaces EPS sizing, Q6).

The company decided not to measure EPS before go-live and to add disk when it
fills up. OpenSearch stops writing at 95% (flood-stage watermark) and new logs
are then lost, so this job warns early: run it hourly, and any path at or above
--warn sends result=WARN to the SIEM, which raises OPS-03.

  python disk_check.py /var/lib/docker
  python disk_check.py /var/lib/docker /mnt/siem-backup --warn 75 --syslog 127.0.0.1:514

Used % is computed like df (used / (used + available)). Exit code is 1 when a
path is at or above --warn, so cron can mail it too.
"""
import argparse
import os
import shutil
import socket
import sys
from datetime import datetime, timezone

GB = 1024 ** 3


def send_syslog(target, message, severity):
    host, _, port = target.rpartition(":")
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    line = f"<{13 * 8 + severity}>1 {ts} {socket.gethostname()} disk-check {os.getpid()} - - {message}"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(line.encode(), (host, int(port)))


def check(path, warn_pct):
    usage = shutil.disk_usage(path)
    used_pct = round(100 * usage.used / (usage.used + usage.free)) if usage.used + usage.free else 0
    result = "WARN" if used_pct >= warn_pct else "PASS"
    return result, (f"action=disk_check path={path} used_pct={used_pct} free_gb={usage.free / GB:.1f} "
                    f"total_gb={usage.total / GB:.1f} warn_pct={warn_pct} result={result}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+", help="mount points to check, e.g. the Docker data root")
    parser.add_argument("--warn", type=int, default=75, metavar="PCT", help="warn at this used %% (default 75)")
    parser.add_argument("--syslog", metavar="HOST:PORT", help="send each result to the SIEM over syslog UDP")
    args = parser.parse_args()
    warned = False
    for path in args.paths:
        if not os.path.isdir(path):
            sys.exit(f"not a directory: {path}")
        result, summary = check(path, args.warn)
        print(summary)
        warned |= result == "WARN"
        if args.syslog:
            send_syslog(args.syslog, summary, 4 if result == "WARN" else 6)
    sys.exit(1 if warned else 0)


if __name__ == "__main__":
    main()
