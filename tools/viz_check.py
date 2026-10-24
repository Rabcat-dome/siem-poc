#!/usr/bin/env python3
"""VIZ-CHECK: is everything the simulator sends visible, alerted on and complete? (POC acceptance)

The POC runs on simulated data only, so its job is to show that every kind of
log ends up in a dashboard with the who / what / where fields filled in. This
script reads the dashboards from Graylog itself (so edits made in the UI count)
and checks, over the last --hours:

  1. widgets      every dashboard widget has data                         FAIL if empty
  2. coverage     every event_type in the data appears in at least one
                  detail widget (a table, pie or message list; a chart over
                  time only shows volume)                                  FAIL if none
  3. alerts       every alert fired at least once                          WARN if not
  4. fields       every event_type carries its who/what/where fields
                  (EXPECTED below); src_owner is checked only for sources
                  in internal zones, where the asset inventory applies,
                  and not for devices NET-03 already reports as unknown  WARN under --min-fill

  python viz_check.py                       # last 24 hours, print the report
  python viz_check.py --hours 4 --out reports

Scenarios fire at random, so a short window can leave widgets empty. On a
fresh stack play every scenario first (generator --play all), wait two
minutes, then check the last hour. WEB-02, NET-04 and WEB-01 run every 5, 10
and 60 minutes, so their alerts can take that long to show up.

Env: GRAYLOG_URL, GRAYLOG_USER, GRAYLOG_PASSWORD, GRAYLOG_CA_FILE (HTTPS).
Exit code 1 when anything FAILs.
"""
import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

URL = os.getenv("GRAYLOG_URL", "http://localhost:9000").rstrip("/")
AUTH = base64.b64encode(f"{os.getenv('GRAYLOG_USER', 'admin')}:{os.getenv('GRAYLOG_PASSWORD', 'admin')}".encode()).decode()
TLS = ssl.create_default_context(cafile=os.environ["GRAYLOG_CA_FILE"]) if os.getenv("GRAYLOG_CA_FILE") else None
BKK = timezone(timedelta(hours=7))
EVENTS_STREAM = "000000000000000000000002"
# sources the asset inventory should name; devices already flagged unknown (NET-03) are left out
INTERNAL = "src_zone:(LAN\\-Office OR Server OR Management OR VPN) AND NOT mac_known:false"

# who / what / where each event type must carry (prefix match on event_type, first match wins)
EXPECTED = [
    ("fw_", ["src_ip", "dst_ip", "src_zone", "dst_zone", "protocol", "fw_rule_desc"]),
    ("ids_alert", ["ids_signature", "ids_priority", "src_ip", "dst_ip", "src_zone", "dst_zone"]),
    ("gui_login_", ["user", "src_ip", "src_zone"]),
    ("config_change", ["user", "src_ip", "changed_via"]),
    ("vpn_auth_", ["vpn_user"]),
    ("vpn_session_start", ["vpn_user", "vpn_assigned_ip", "src_ip"]),
    ("vpn_tls_error", ["src_ip"]),
    ("dhcp_lease", ["src_ip", "src_mac", "dhcp_hostname", "src_zone"]),
    ("dns_blocked", ["src_ip", "src_zone", "dns_query", "web_category"]),
    ("dns_", ["src_ip", "src_zone", "dns_query"]),
    ("port_security_violation", ["net_device", "net_port", "src_mac"]),
    ("port_", ["net_device", "net_port"]),
    ("device_config_change", ["net_device", "user", "src_ip"]),
    ("device_login_", ["net_device", "user", "src_ip", "src_zone"]),
    ("wifi_", ["net_device", "src_mac", "wifi_ssid", "src_zone"]),
    ("disk_check", ["path", "disk_used_pct", "result"]),
    ("log_manifest_verify", ["result", "ok", "mismatch", "missing"]),
    ("log_manifest_create", ["new_files", "manifest"]),
]
# alerts the simulator's random scenarios never raise, and how to raise them by hand
MANUAL = {
    "OPS-01": "docker compose stop generator, wait 6 minutes",
    "OPS-02": "generator --play integrity_fail",
    "OPS-03": "generator --play disk_full",
    "IAM-03": "fires only 19:00-07:59 Bangkok time",
    # not manual, but checked once per window (provision.py every_min), so a fresh play shows up late
    "WEB-02": "checked every 5 minutes",
    "NET-04": "checked every 10 minutes",
    "WEB-01": "checked every hour",
}


def api(method, path, body=None):
    req = urllib.request.Request(URL + path, method=method, data=json.dumps(body).encode() if body is not None else None)
    for k, v in {"Authorization": f"Basic {AUTH}", "Content-Type": "application/json",
                 "Accept": "application/json", "X-Requested-By": "viz-check"}.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60, context=TLS) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path} -> {e.code}: {e.read().decode(errors='replace')[:400]}")


class Search:
    def __init__(self, hours):
        # one fixed window for every query, so totals and "has field" counts cover the same messages;
        # it ends a minute ago, so messages still being indexed do not land between two counts
        end = datetime.now(timezone.utc) - timedelta(minutes=1)
        fmt = lambda d: d.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        self.timerange = {"type": "absolute", "from": fmt(end - timedelta(hours=hours)), "to": fmt(end)}

    def rows(self, query, group_by, streams=None, limit=100):
        body = {"query": query or "*", "timerange": self.timerange,
                "group_by": [{"field": f, "limit": limit} for f in group_by], "metrics": [{"function": "count"}]}
        if streams:
            body["streams"] = streams
        return api("POST", "/api/search/aggregate", body).get("datarows", [])

    def count(self, query, streams=None):
        # the scripting API needs a grouping; every message has a source
        return int(sum(r[-1] for r in self.rows(query, ["source"], streams, limit=1000)))


def and_(query, extra):
    return f"({query}) AND {extra}" if query and query != "*" else extra


def dashboards():
    """[(dashboard, widget title, kind, query, streams, fields, detail)] from the provisioned SIEM dashboards."""
    out = []
    for v in api("GET", "/api/views?per_page=200")["views"]:
        if v["type"] != "DASHBOARD" or not v["title"].startswith("SIEM - "):
            continue
        view = api("GET", f"/api/views/{v['id']}")
        for state in view["state"].values():
            titles = state.get("titles", {}).get("widget", {})
            for w in state["widgets"]:
                cfg = w.get("config", {})
                if w["type"] == "messages":
                    fields = [f for f in cfg.get("fields", []) if f != "timestamp"]
                    kind, detail = "messages", True
                else:
                    pivots = cfg.get("row_pivots", []) + cfg.get("column_pivots", [])
                    rows = [f for p in cfg.get("row_pivots", []) for f in p["fields"]]
                    fields = [f for p in pivots for f in p["fields"] if f != "timestamp"]
                    kind = cfg.get("visualization", "table")
                    detail = kind != "numeric" and any(f != "timestamp" for f in rows)
                out.append((v["title"], titles.get(w["id"], w["id"]), kind, w["query"]["query_string"],
                            w.get("streams", []), fields, detail))
    return out


def check(hours, min_fill):
    s = Search(hours)
    report, fails, warns = [], 0, 0

    # 1 + 2: widgets and event type coverage
    widgets = dashboards()
    seen_types = {r[0]: r[1] for r in s.rows("_exists_:event_type", ["event_type"])}
    detail_cover, trend_cover = {}, {}
    report.append(f"## 1. Widgets ({len(widgets)})\n\n| Dashboard | Widget | ชนิด | ข้อความ | Field ที่แสดง (% มีค่า) | ผล |\n|---|---|---|---|---|---|")
    for dash, title, kind, query, streams, fields, detail in widgets:
        n = s.count(query, streams)
        fill = []
        for f in fields:
            if f in ("event_definition_id", "priority") or not n:
                continue
            pct = 100 * s.count(and_(query, f"_exists_:{f}"), streams) / n
            fill.append(f"{f} {pct:.0f}%")
        if EVENTS_STREAM not in streams:
            for (et, _) in s.rows(query, ["event_type"], streams):
                (detail_cover if detail else trend_cover).setdefault(et, []).append(f"{dash.removeprefix('SIEM - ')} › {title}")
        result = "PASS" if n else "**FAIL** ว่าง"
        fails += not n
        report.append(f"| {dash.removeprefix('SIEM - ')} | {title} | {kind} | {n:,} | {' · '.join(fill) or '-'} | {result} |")

    report.append(f"\n## 2. Event type ที่มีในข้อมูล ({len(seen_types)}) และ widget ที่แสดง\n\n"
                  "| event_type | ข้อความ | Widget แบบละเอียด | ผล |\n|---|---|---|---|")
    for et, n in sorted(seen_types.items()):
        where = detail_cover.get(et, [])
        ok = bool(where)
        fails += not ok
        shown = "<br>".join(where[:3]) + (f"<br>(+{len(where) - 3})" if len(where) > 3 else "") if where else \
            ("มีแค่กราฟตามเวลา" if et in trend_cover else "ไม่มี")
        report.append(f"| {et} | {n:,} | {shown} | {'PASS' if ok else '**FAIL**'} |")

    # 3: alerts
    definitions = [d for d in api("GET", "/api/events/definitions?per_page=200")["event_definitions"]
                   if d["title"].startswith("[")]  # ours are "[ID] title"; skip Graylog's built-in ones
    fired = {r[0]: r[1] for r in s.rows("*", ["event_definition_id"], [EVENTS_STREAM])}
    report.append(f"\n## 3. Alert ({len(definitions)})\n\n| Alert | เกิดกี่ครั้ง | ผล |\n|---|---|---|")
    for d in sorted(definitions, key=lambda d: d["title"]):
        n = fired.get(d["id"], 0)
        alert_id = d["title"].split("]")[0].lstrip("[")
        note = "PASS" if n else f"WARN ยังไม่เกิด ({MANUAL.get(alert_id, 'ดู scenario ใน simulator')})"
        warns += not n
        report.append(f"| {d['title']} | {n:,} | {note} |")

    # 4: fields per event type
    report.append(f"\n## 4. ความครบของ field ต่อ event_type (เกณฑ์ {min_fill}%)\n\n"
                  "| event_type | Field ที่ต้องมี (% มีค่า) | src_owner ของต้นทางภายใน | ผล |\n|---|---|---|---|")
    for et, n in sorted(seen_types.items()):
        expected = next((fields for prefix, fields in EXPECTED if et.startswith(prefix)), [])
        cells, low = [], []
        for f in expected:
            pct = 100 * s.count(f"event_type:{et} AND _exists_:{f}") / n
            cells.append(f"{f} {pct:.0f}%")
            if pct < min_fill:
                low.append(f)
        internal = s.count(f"event_type:{et} AND _exists_:src_ip AND {INTERNAL}")
        owner = "-"
        if internal:
            pct = 100 * s.count(f"event_type:{et} AND _exists_:src_ip AND {INTERNAL} AND _exists_:src_owner") / internal
            owner = f"{pct:.0f}% ของ {internal:,}"
            if pct < min_fill:
                low.append("src_owner")
        if not expected:
            low.append("(ไม่ได้กำหนด field ที่ต้องมีใน EXPECTED)")
        warns += bool(low)
        report.append(f"| {et} | {' · '.join(cells) or '-'} | {owner} | {'PASS' if not low else 'WARN ' + ', '.join(low)} |")

    return report, fails, warns


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hours", type=float, default=24, help="time window (default 24; 0.25 = last 15 minutes)")
    parser.add_argument("--min-fill", type=int, default=95, help="%% of messages that must carry each field (default 95)")
    parser.add_argument("--out", help="also write the report as Markdown into this folder")
    args = parser.parse_args()
    report, fails, warns = check(args.hours, args.min_fill)
    now = datetime.now(BKK)
    head = (f"# VIZ-CHECK: ความครบถ้วนของข้อมูลที่ visualize\n\nช่วง {args.hours:g} ชั่วโมงล่าสุด ถึง {now:%Y-%m-%d %H:%M} "
            f"(เวลาไทย) · Graylog {URL} · **FAIL {fails} · WARN {warns}**\n")
    text = head + "\n" + "\n".join(report) + "\n"
    print(text)
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        path = os.path.join(args.out, f"VIZ-CHECK_{now:%Y%m%d-%H%M}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote {path}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
