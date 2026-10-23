#!/usr/bin/env python3
"""SHA-256 manifest for archived log files (NFR-11, ISO A.8.15 / A.5.28).

  create : hash every archive file that is not in a manifest yet and write
           manifest-<timestamp>.sha256 (same format as `sha256sum`)
  verify : re-hash every file listed in all manifests and report
           OK / MISMATCH / MISSING, plus files that no manifest covers yet

Keep the manifest folder apart from the archive folder (ideally a WriteOnce
share), so whoever can touch the logs cannot also rewrite their hashes.

  python log_manifest.py create /volume1/log-archive /volume1/log-manifest
  python log_manifest.py verify /volume1/log-archive /volume1/log-manifest --syslog graylog:1514

Exit code is 1 when verify finds a mismatch or a missing file, so cron can
mail the failure; --syslog also sends a one-line result to the SIEM (OPS-02).
"""
import argparse
import hashlib
import os
import socket
import sys
from datetime import datetime, timezone

CHUNK = 1024 * 1024


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def archive_files(archive_dir):
    for root, _, files in os.walk(archive_dir):
        for name in sorted(files):
            if name.startswith("."):
                continue
            full = os.path.join(root, name)
            yield os.path.relpath(full, archive_dir).replace(os.sep, "/"), full


def read_manifests(manifest_dir):
    """{relative path: (hash, manifest file)}; the first manifest that lists a file wins."""
    listed = {}
    for name in sorted(os.listdir(manifest_dir)):
        if not (name.startswith("manifest-") and name.endswith(".sha256")):
            continue
        with open(os.path.join(manifest_dir, name), encoding="utf-8") as f:
            for line in f:
                digest, _, rel = line.rstrip("\n").partition("  ")
                if rel and rel not in listed:
                    listed[rel] = (digest, name)
    return listed


def send_syslog(target, message, severity):
    host, _, port = target.rpartition(":")
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    line = f"<{13 * 8 + severity}>1 {ts} {socket.gethostname()} log-manifest {os.getpid()} - - {message}"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(line.encode(), (host, int(port)))


def create(args):
    listed = read_manifests(args.manifest_dir)
    new = [(rel, full) for rel, full in archive_files(args.archive_dir) if rel not in listed]
    if not new:
        print("no new files to hash")
        return 0
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    out = os.path.join(args.manifest_dir, f"manifest-{stamp}.sha256")
    with open(out, "x", encoding="utf-8") as f:  # never overwrite an existing manifest
        for rel, full in new:
            f.write(f"{sha256(full)}  {rel}\n")
    print(f"hashed {len(new)} new file(s) -> {out}")
    if args.syslog:
        send_syslog(args.syslog, f"action=create new_files={len(new)} manifest={os.path.basename(out)}", 6)
    return 0


def verify(args):
    listed = read_manifests(args.manifest_dir)
    on_disk = dict(archive_files(args.archive_dir))
    ok, mismatch, missing = 0, [], []
    for rel, (digest, manifest) in sorted(listed.items()):
        full = on_disk.get(rel)
        if full is None:
            missing.append((rel, manifest))
        elif sha256(full) != digest:
            mismatch.append((rel, manifest))
        else:
            ok += 1
    unlisted = sorted(set(on_disk) - set(listed))

    for rel, manifest in mismatch:
        print(f"MISMATCH  {rel}  (hash from {manifest})")
    for rel, manifest in missing:
        print(f"MISSING   {rel}  (listed in {manifest})")
    for rel in unlisted:
        print(f"UNLISTED  {rel}  (run create to add it)")
    summary = (f"action=verify result={'FAIL' if mismatch or missing else 'PASS'} ok={ok} "
               f"mismatch={len(mismatch)} missing={len(missing)} unlisted={len(unlisted)}")
    print(summary)
    if args.syslog:
        send_syslog(args.syslog, summary, 3 if mismatch or missing else 6)
    return 1 if mismatch or missing else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=["create", "verify"])
    parser.add_argument("archive_dir")
    parser.add_argument("manifest_dir")
    parser.add_argument("--syslog", metavar="HOST:PORT", help="send the result to the SIEM over syslog UDP")
    args = parser.parse_args()
    for d in (args.archive_dir, args.manifest_dir):
        if not os.path.isdir(d):
            sys.exit(f"not a directory: {d}")
    sys.exit(create(args) if args.action == "create" else verify(args))


if __name__ == "__main__":
    main()
