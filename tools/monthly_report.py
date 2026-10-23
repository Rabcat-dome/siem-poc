#!/usr/bin/env python3
"""RPT-01: monthly security report from Graylog, for management review (ISO Clause 9.3).

Graylog Open has no scheduled reports, so this script pulls the numbers through
the Graylog search API and writes one self-contained HTML file (print to PDF
for the evidence folder). Use a read-only account such as it-analyst.

  python monthly_report.py                      # previous calendar month
  python monthly_report.py --month 2026-10
  python monthly_report.py --last-days 7 --email-to management@example.local

Env: GRAYLOG_URL, GRAYLOG_USER, GRAYLOG_PASSWORD, GRAYLOG_CA_FILE (HTTPS), SMTP_HOST, SMTP_PORT,
     SMTP_USER, SMTP_PASSWORD, SMTP_STARTTLS (true|false), REPORT_FROM
"""
import argparse
import base64
import html
import json
import os
import smtplib
import ssl
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

BKK = timezone(timedelta(hours=7))  # Thailand has no DST
URL = os.getenv("GRAYLOG_URL", "http://localhost:9000").rstrip("/")
AUTH = base64.b64encode(f"{os.getenv('GRAYLOG_USER', 'admin')}:{os.getenv('GRAYLOG_PASSWORD', 'admin')}".encode()).decode()
EMPTY = ("(Empty Value)", "-", None)
# Unbound blocklist answers; keep in step with DNS_BLOCKED in provisioner/provision.py
DNS_BLOCKED = "event_type:dns_blocked"
# production Graylog is HTTPS with the private CA from tools/gen_tls_certs.sh
TLS = ssl.create_default_context(cafile=os.environ["GRAYLOG_CA_FILE"]) if os.getenv("GRAYLOG_CA_FILE") else None


def api(method, path, body=None):
    req = urllib.request.Request(URL + path, method=method, data=json.dumps(body).encode() if body is not None else None)
    for k, v in {"Authorization": f"Basic {AUTH}", "Content-Type": "application/json",
                 "Accept": "application/json", "X-Requested-By": "rpt-01"}.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60, context=TLS) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path} -> {e.code}: {e.read().decode(errors='replace')[:400]}")


class Period:
    def __init__(self, start, end, label):
        self.start, self.end, self.label = start, end, label

    def timerange(self, start=None, end=None):
        fmt = lambda d: d.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return {"type": "absolute", "from": fmt(start or self.start), "to": fmt(end or self.end)}


def period_from_args(args):
    now = datetime.now(BKK)
    if args.last_days:
        end = now
        return Period(end - timedelta(days=args.last_days), end, f"last-{args.last_days}d-{end:%Y%m%d}")
    if args.month:
        year, month = map(int, args.month.split("-"))
    else:
        first_this = now.replace(day=1)
        prev = first_this - timedelta(days=1)
        year, month = prev.year, prev.month
    start = datetime(year, month, 1, tzinfo=BKK)
    end = datetime(year + (month == 12), month % 12 + 1, 1, tzinfo=BKK)
    return Period(start, end, f"{year}-{month:02d}")


def aggregate(period, query, fields, limit=10, start=None, end=None):
    body = {"query": query, "timerange": period.timerange(start, end),
            "group_by": [{"field": f, "limit": limit} for f in fields],
            "metrics": [{"function": "count", "sort": "desc"}]}
    return api("POST", "/api/search/aggregate", body).get("datarows", [])


def count(period, query, start=None, end=None):
    # the scripting API needs a grouping, and every message has a source
    return int(sum(r[-1] for r in aggregate(period, query, ["source"], limit=1000, start=start, end=end)))


def messages(period, query, fields, size=200):
    body = {"query": query, "timerange": period.timerange(), "fields": fields, "size": size,
            "sort": "timestamp", "sort_order": "asc"}
    return api("POST", "/api/search/messages", body).get("datarows", [])


def alerts(period):
    events, page = [], 1
    while True:
        res = api("POST", "/api/events/search", {"query": "", "page": page, "per_page": 100,
                                                 "filter": {"alerts": "only"}, "timerange": period.timerange()})
        batch = [e["event"] for e in res.get("events", [])]
        events += batch
        if len(batch) < 100:
            return events
        page += 1


# --- HTML -----------------------------------------------------------------

def esc(v):
    if v in EMPTY:
        return '<span class="na">ไม่ทราบ</span>'
    return html.escape(str(v))


def local_time(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone(BKK).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return ts


def table(headers, rows, empty="ไม่มีรายการในช่วงนี้"):
    if not rows:
        return f'<p class="empty">{empty}</p>'
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{esc(c)}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def section(title, iso, intro, content):
    return (f'<section><h2>{html.escape(title)}</h2><p class="iso">{html.escape(iso)}</p>'
            f'<p class="intro">{html.escape(intro)}</p>{content}</section>')


PRIORITY = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def build(period):
    total = count(period, "*")
    by_cat = aggregate(period, "*", ["event_category"], limit=20)

    days, silent = [], []
    day = period.start
    while day < min(period.end, datetime.now(BKK)):
        n = count(period, "event_source:opnsense", start=day, end=day + timedelta(days=1))
        days.append((f"{day:%Y-%m-%d}", n))
        if n == 0:
            silent.append(f"{day:%Y-%m-%d}")
        day += timedelta(days=1)

    events = alerts(period)
    by_alert = Counter((e["message"].split(":")[0], PRIORITY.get(e.get("priority"), e.get("priority"))) for e in events)
    alert_rows = [(title, prio, n) for (title, prio), n in by_alert.most_common()]

    s = []
    s.append(section("1. ภาพรวม", "A.8.15 Logging · A.8.16 Monitoring",
                     f"log ทั้งหมด {total:,} รายการ และ alert {len(events):,} ครั้ง "
                     f"มีวันที่ไม่มี log จาก OPNsense {len(silent)} วัน",
                     table(["หมวด log", "จำนวน"], by_cat)
                     + (f'<p class="warn">วันที่ไม่มี log: {", ".join(silent)} ต้องตรวจสอบว่า firewall หรือ logging หยุดทำงานหรือไม่</p>' if silent else "")))
    s.append(section("2. Alert", "A.5.24–A.5.26 Incident management",
                     "จำนวน alert แยกตาม use case ทุก alert ระดับ High ควรมี ticket/บันทึกการตรวจสอบแนบ",
                     table(["Alert", "Priority", "จำนวนครั้ง"], alert_rows)))
    s.append(section("3. Web filtering", "A.8.23 Web filtering",
                     "หมวดเว็บที่ถูกบล็อก เครื่องที่พยายามเข้าบ่อย และการพยายามเลี่ยง DNS filtering",
                     "<h3>หมวดที่ถูกบล็อก</h3>" + table(["หมวด", "จำนวน query"], aggregate(period, DNS_BLOCKED, ["web_category"]))
                     + "<h3>เครื่องที่ query หมวดที่ถูกบล็อกมากที่สุด</h3>"
                     + table(["IP", "เครื่อง", "เจ้าของ", "จำนวน"], aggregate(period, DNS_BLOCKED, ["src_ip", "src_host", "src_owner"]))
                     + "<h3>หมวดที่ monitor (อนุญาตแต่บันทึก)</h3>" + table(["หมวด", "จำนวน query"], aggregate(period, "web_policy:monitor", ["web_category"]))
                     + "<h3>พยายามเลี่ยง DNS filtering</h3>"
                     + table(["IP", "เครื่อง", "จำนวน"], aggregate(period, "fw_rule_tag:dns\\-bypass", ["src_ip", "src_host"]))))
    s.append(section("4. Network", "A.8.20 Network security · A.8.22 Segregation",
                     "แหล่งที่ถูก firewall บล็อกมากที่สุด port ที่ถูกบล็อก และการละเมิดการแบ่ง zone",
                     "<h3>Source ที่ถูกบล็อกมากที่สุด</h3>" + table(["IP", "Zone", "จำนวน"], aggregate(period, "fw_action:block", ["src_ip", "src_zone"]))
                     + "<h3>Port ปลายทางที่ถูกบล็อก</h3>" + table(["Port", "จำนวน"], aggregate(period, "fw_action:block", ["dst_port"]))
                     + "<h3>Guest พยายามเข้าโซนภายใน</h3>"
                     + table(["IP", "Zone ปลายทาง", "จำนวน"], aggregate(period, "src_zone:Guest AND fw_action:block AND NOT dst_zone:Internet", ["src_ip", "dst_zone"]))))
    s.append(section("5. ภัยคุกคาม", "A.5.7 Threat intelligence · A.8.7 Malware",
                     "IDS alert และการติดต่อกับ IOC ใน threat intel",
                     "<h3>IDS signature</h3>" + table(["Signature", "Priority", "จำนวน"], aggregate(period, "event_type:ids_alert", ["ids_signature", "ids_priority"]))
                     + "<h3>Threat intel hits</h3>" + table(["IOC", "หมวด", "จำนวน"], aggregate(period, "threat_indicator:true", ["threat_ioc", "threat_category"]))))
    logins = messages(period, "event_type:gui_login_success", ["timestamp", "user", "src_ip", "src_zone"])
    changes = messages(period, "event_type:config_change", ["timestamp", "user", "src_ip", "changed_via"])
    s.append(section("6. สิทธิ์ admin และการเปลี่ยนแปลง", "A.8.2 Privileged access · A.8.9 / A.8.32 Change management",
                     "ผู้ตรวจต้องเทียบทุกการแก้ config กับ change request และเติมเลขที่ในคอลัมน์สุดท้าย",
                     "<h3>Admin login สำเร็จ</h3>" + table(["เวลา", "User", "IP", "Zone"], [(local_time(r[0]), *r[1:]) for r in logins])
                     + "<h3>Config change</h3>" + table(["เวลา", "User", "IP", "แก้ผ่าน", "Change request #"],
                                                       [(local_time(r[0]), *r[1:], "") for r in changes])))
    unknown = aggregate(period, "(mac_known:false AND src_zone:LAN\\-Office) OR event_type:port_security_violation",
                        ["src_mac", "event_type", "net_device"])
    dev_logins = messages(period, "event_type:device_login_success", ["timestamp", "net_device", "user", "src_ip", "src_zone"])
    dev_changes = messages(period, "event_type:device_config_change", ["timestamp", "net_device", "user", "src_ip"])
    s.append(section("7. อุปกรณ์เครือข่าย (switch / Wi-Fi)", "A.5.9 Inventory of assets · A.8.2 · A.8.9 / A.8.32",
                     "เครื่องที่ไม่อยู่ในทะเบียน asset ที่เข้ามาในโซน Office, การ login หน้า admin ของ switch/AP และการแก้ config",
                     "<h3>เครื่องที่ไม่อยู่ในทะเบียน asset</h3>" + table(["MAC", "เห็นจาก", "อุปกรณ์", "จำนวน"], unknown)
                     + "<h3>Admin login สำเร็จที่ switch / AP</h3>"
                     + table(["เวลา", "อุปกรณ์", "User", "IP", "Zone"], [(local_time(r[0]), *r[1:]) for r in dev_logins])
                     + "<h3>Config change ของ switch / AP</h3>"
                     + table(["เวลา", "อุปกรณ์", "User", "IP", "Change request #"], [(local_time(r[0]), *r[1:], "") for r in dev_changes])))
    verifies = messages(period, "event_type:log_manifest_verify", ["timestamp", "source", "result", "ok", "mismatch", "missing"])
    s.append(section("8. ความถูกต้องของ log archive", "A.8.15 Logging · A.5.28 Evidence (NFR-11)",
                     "ผลการตรวจ SHA-256 manifest ของไฟล์ archive (ควรมีอย่างน้อยเดือนละครั้งและผลเป็น PASS)",
                     table(["เวลา", "เครื่อง", "ผล", "OK", "Mismatch", "Missing"], [(local_time(r[0]), *r[1:]) for r in verifies],
                           empty="ไม่มีการตรวจในช่วงนี้ ต้องรัน tools/log_manifest.py verify")))
    disk = aggregate(period, "event_type:disk_check", ["source", "path", "result"], limit=50)
    peak = aggregate(period, "event_type:disk_check", ["source", "path", "used_pct"], limit=1000)
    highest = {}
    for host, path, pct, _ in peak:
        try:
            highest[(host, path)] = max(highest.get((host, path), 0), int(pct))
        except (TypeError, ValueError):
            pass
    s.append(section("9. พื้นที่ disk ของ SIEM", "A.8.6 Capacity management (Q6, OPS-03)",
                     "ไม่ได้วัด EPS ก่อนขึ้นระบบ จึงใช้ผลตรวจ disk รายชั่วโมงแทน ถ้ามีผล WARN ให้วางแผนขยาย disk",
                     table(["เครื่อง", "Path", "ผล", "จำนวนครั้ง"], disk, empty="ไม่มีผลตรวจในช่วงนี้ ต้องตั้ง job disk-check")
                     + (table(["เครื่อง", "Path", "ใช้สูงสุด (%)"], [(h, p, v) for (h, p), v in sorted(highest.items())]) if highest else "")))
    s.append(section("10. ความต่อเนื่องของ log รายวัน", "A.8.15 · A.8.16", "จำนวน log จาก OPNsense ต่อวัน",
                     table(["วันที่", "จำนวน log"], days)))
    return s, total, len(events)


PAGE = """<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>RPT-01 {label}</title>
<style>
:root {{ --ink:#2d3142; --muted:#4f5d75; --rule:rgba(45,49,66,.14); --accent:#bf4520; }}
body {{ font: 14px/1.55 system-ui, 'Noto Sans Thai', sans-serif; color: var(--ink); background: #f5f5f5; margin: 0; padding: 32px 16px; }}
main {{ max-width: 960px; margin: 0 auto; }}
h1 {{ font-size: 26px; margin: 0 0 4px; }} h2 {{ font-size: 18px; margin: 0; }} h3 {{ font-size: 14px; margin: 18px 0 6px; }}
.meta, .iso, .intro {{ color: var(--muted); margin: 4px 0; }} .iso {{ font: 12px ui-monospace, monospace; }}
section {{ background: #fff; border: 1px solid var(--rule); border-radius: 6px; padding: 18px 20px; margin-top: 16px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 6px; }}
th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--rule); vertical-align: top; }}
th {{ font-size: 12px; color: var(--muted); font-weight: 600; }}
.na, .empty {{ color: var(--muted); font-style: italic; }} .warn {{ color: var(--accent); font-weight: 600; }}
.sign td {{ height: 36px; }}
@media print {{ body {{ background: #fff; padding: 0; }} section {{ break-inside: avoid; }} }}
</style></head><body><main>
<h1>รายงานความมั่นคงปลอดภัยประจำเดือน (RPT-01)</h1>
<p class="meta">ช่วงเวลา {start} ถึง {end} (เวลาไทย) · สร้างเมื่อ {generated} · แหล่งข้อมูล Graylog {url}</p>
{sections}
<section><h2>การทบทวนโดยฝ่ายบริหาร</h2><p class="iso">ISO/IEC 27001:2022 Clause 9.3 Management review</p>
<table class="sign"><tr><th>ผู้ทบทวน</th><td></td><th>วันที่</th><td></td></tr>
<tr><th>ข้อสังเกต / สิ่งที่ต้องดำเนินการ</th><td colspan="3"></td></tr><tr><th>ลงชื่อ</th><td colspan="3"></td></tr></table></section>
</main></body></html>"""


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    when = parser.add_mutually_exclusive_group()
    when.add_argument("--month", help="YYYY-MM (default: previous month)")
    when.add_argument("--last-days", type=int, help="report on the last N days instead of a calendar month")
    parser.add_argument("--out", default=os.getenv("REPORT_DIR", "reports"))
    parser.add_argument("--email-to", help="also send the report by e-mail (SMTP_HOST / SMTP_PORT)")
    args = parser.parse_args()

    period = period_from_args(args)
    sections, total, n_alerts = build(period)
    page = PAGE.format(label=period.label, start=f"{period.start:%Y-%m-%d %H:%M}", end=f"{period.end:%Y-%m-%d %H:%M}",
                       generated=f"{datetime.now(BKK):%Y-%m-%d %H:%M}", url=html.escape(URL), sections="".join(sections))
    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, f"RPT-01_{period.label}.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"wrote {path}: {total:,} log messages, {n_alerts} alerts")

    if args.email_to:
        msg = EmailMessage()
        msg["Subject"] = f"[SIEM] RPT-01 รายงานประจำ {period.label}"
        msg["From"] = os.getenv("REPORT_FROM", "siem-poc@example.local")
        msg["To"] = args.email_to
        msg.set_content(f"รายงาน RPT-01 ช่วง {period.label}: log {total:,} รายการ, alert {n_alerts} ครั้ง ดูไฟล์แนบ")
        msg.add_attachment(page.encode("utf-8"), maintype="text", subtype="html", filename=os.path.basename(path))
        with smtplib.SMTP(os.getenv("SMTP_HOST", "localhost"), int(os.getenv("SMTP_PORT", "25")), timeout=30) as smtp:
            if os.getenv("SMTP_STARTTLS", "false").lower() == "true":
                smtp.starttls(context=ssl.create_default_context())
            if os.getenv("SMTP_USER"):
                smtp.login(os.environ["SMTP_USER"], os.getenv("SMTP_PASSWORD", ""))
            smtp.send_message(msg)
        print(f"sent to {args.email_to}")


if __name__ == "__main__":
    main()
