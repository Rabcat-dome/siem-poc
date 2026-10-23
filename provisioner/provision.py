#!/usr/bin/env python3
"""Provision Graylog for the OPNsense SIEM POC via its REST API.

Creates (idempotently, matched by title/name):
  inputs -> lookup tables -> pipeline rules + pipeline -> streams -> notifications -> alerts

Safe to re-run: existing objects are left as they are, except pipeline rules,
the pipeline and alerts, which are updated so edits in this repo apply.
"""
import base64
import glob
import json
import os
import sys
import time
import urllib.error
import urllib.request

URL = os.getenv("GRAYLOG_URL", "http://localhost:9000").rstrip("/")
AUTH = base64.b64encode(f"{os.getenv('GRAYLOG_USER', 'admin')}:{os.getenv('GRAYLOG_PASSWORD', 'admin')}".encode()).decode()
CONF_DIR = os.getenv("GRAYLOG_CONF_DIR", "/graylog")
LOOKUP_DIR_IN_GRAYLOG = "/usr/share/graylog/data/lookup"
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "soc-team@example.local")
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "http://webhook:8088/alert")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "1514"))
DEFAULT_STREAM = "000000000000000000000001"
EVENTS_STREAM = "000000000000000000000002"  # "All events"


def api(method, path, body=None, ok=(200, 201, 204)):
    req = urllib.request.Request(URL + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Authorization", f"Basic {AUTH}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    req.add_header("X-Requested-By", "siem-poc-provisioner")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        raise RuntimeError(f"{method} {path} -> {e.code}: {detail[:800]}") from None


def wait_for_graylog():
    for _ in range(90):
        try:
            if api("GET", "/api/system").get("lifecycle") == "running":
                return
        except Exception:
            pass
        time.sleep(5)
    sys.exit("Graylog did not become ready")


def log(kind, title, created):
    print(f"  {'+ created' if created else '= exists '} {kind}: {title}")


# --- inputs ---------------------------------------------------------------

def ensure_inputs():
    existing = {i["title"]: i for i in api("GET", "/api/system/inputs")["inputs"]}
    states = {s["id"]: s["state"] for s in api("GET", "/api/system/inputstates")["states"]}
    for proto, cls in (("UDP", "org.graylog2.inputs.syslog.udp.SyslogUDPInput"),
                       ("TCP", "org.graylog2.inputs.syslog.tcp.SyslogTCPInput")):
        title = f"OPNsense Syslog {proto} {SYSLOG_PORT}"
        if title in existing:
            input_id = existing[title]["id"]
            log("input", title, False)
            if states.get(input_id) not in ("RUNNING", "STARTING"):
                api("PUT", f"/api/system/inputstates/{input_id}")
        else:
            cfg = {"bind_address": "0.0.0.0", "port": SYSLOG_PORT, "recv_buffer_size": 1048576,
                   "number_worker_threads": 2, "override_source": None, "force_rdns": False,
                   "allow_override_date": True, "store_full_message": True,
                   "expand_structured_data": False, "timezone": "Asia/Bangkok"}
            if proto == "TCP":
                cfg.update({"tls_enable": False, "use_null_delimiter": False, "max_message_size": 2097152})
            api("POST", "/api/system/inputs", {"title": title, "type": cls, "global": True, "configuration": cfg})
            log("input", title, True)  # new inputs start on their own


# --- lookup tables ----------------------------------------------------------

LOOKUPS = [
    # name, csv file, key column, value column, cidr keys, default value
    # (the CSV adapter returns one column, so the asset inventory is exposed as one table per column)
    ("asset-hostname", "assets.csv", "ip", "hostname", False, None),
    ("asset-owner", "assets.csv", "ip", "owner", False, None),
    ("asset-department", "assets.csv", "ip", "department", False, None),
    ("asset-criticality", "assets.csv", "ip", "criticality", False, None),
    ("network-zones", "network_zones.csv", "cidr", "zone", True, "Internet"),
    ("fw-rules", "fw_rules.csv", "rid", "description", False, None),
    ("threat-intel-ip", "threat_intel_ip.csv", "ip", "category", False, None),
    ("threat-intel-domain", "threat_intel_domain.csv", "domain", "category", False, None),
]


def ensure_lookups():
    adapters = {a["name"]: a for a in api("GET", "/api/system/lookup/adapters?per_page=200")["data_adapters"]}
    caches = {c["name"]: c for c in api("GET", "/api/system/lookup/caches?per_page=200")["caches"]}
    tables = {t["name"]: t for t in api("GET", "/api/system/lookup/tables?per_page=200")["lookup_tables"]}

    cache_name = "poc-cache-60s"
    created = cache_name not in caches
    if created:
        caches[cache_name] = api("POST", "/api/system/lookup/caches", {
            "title": "POC cache (60s)", "name": cache_name, "description": "Shared in-memory cache",
            "config": {"type": "guava_cache", "max_size": 10000, "expire_after_access": 60,
                       "expire_after_access_unit": "SECONDS", "expire_after_write": 0,
                       "expire_after_write_unit": None, "ignore_null": False,
                       "ttl_empty": None, "ttl_empty_unit": None}})
    log("lookup cache", cache_name, created)

    for name, csv, key, value, cidr, default in LOOKUPS:
        if name not in adapters:
            adapters[name] = api("POST", "/api/system/lookup/adapters", {
                "title": f"CSV {csv} ({value})", "name": name, "description": f"{LOOKUP_DIR_IN_GRAYLOG}/{csv}",
                "config": {"type": "csvfile", "path": f"{LOOKUP_DIR_IN_GRAYLOG}/{csv}", "separator": ",",
                           "quotechar": "\"", "key_column": key, "value_column": value, "check_interval": 60,
                           "case_insensitive_lookup": True, "multi_value_lookup": False, "cidr_lookup": cidr}})
            log("lookup adapter", name, True)
        if name not in tables:
            api("POST", "/api/system/lookup/tables", {
                "title": name, "name": name, "description": f"from {csv}",
                "cache_id": caches[cache_name]["id"], "data_adapter_id": adapters[name]["id"],
                "default_single_value": default or "", "default_single_value_type": "STRING" if default else "NULL",
                "default_multi_value": "", "default_multi_value_type": "NULL"})
            log("lookup table", name, True)
        else:
            log("lookup table", name, False)


# --- pipeline ---------------------------------------------------------------

def ensure_pipeline():
    rules = {r["title"]: r for r in api("GET", "/api/system/pipelines/rule")}
    for path in sorted(glob.glob(f"{CONF_DIR}/pipeline/*.rule")):
        source = open(path, encoding="utf-8").read()
        title = source.split('"')[1]
        body = {"title": title, "description": os.path.basename(path), "source": source}
        if title in rules:
            body["id"] = rules[title]["id"]
            api("PUT", f"/api/system/pipelines/rule/{rules[title]['id']}", body)
            print(f"  ~ updated  rule: {title}")
        else:
            api("POST", "/api/system/pipelines/rule", body)
            log("rule", title, True)

    source = open(f"{CONF_DIR}/pipeline/opnsense.pipeline", encoding="utf-8").read()
    title = source.split('"')[1]
    pipelines = {p["title"]: p for p in api("GET", "/api/system/pipelines/pipeline")}
    body = {"title": title, "description": "Parse, enrich and route OPNsense logs", "source": source}
    if title in pipelines:
        pid = pipelines[title]["id"]
        api("PUT", f"/api/system/pipelines/pipeline/{pid}", {**body, "id": pid})
        print(f"  ~ updated  pipeline: {title}")
    else:
        pid = api("POST", "/api/system/pipelines/pipeline", body)["id"]
        log("pipeline", title, True)

    conn = {c["stream_id"]: c for c in api("GET", "/api/system/pipelines/connections")}
    ids = set(conn.get(DEFAULT_STREAM, {}).get("pipeline_ids", [])) | {pid}
    api("POST", "/api/system/pipelines/connections/to_stream", {"stream_id": DEFAULT_STREAM, "pipeline_ids": sorted(ids)})
    print("  = pipeline connected to Default Stream")


# --- streams ----------------------------------------------------------------

STREAMS = [
    ("OPNsense - firewall", "pf filterlog: allow/block, who -> where"),
    ("OPNsense - ids", "Suricata IDS/IPS alerts"),
    ("OPNsense - auth", "Firewall web GUI logins"),
    ("OPNsense - config", "Firewall configuration changes (change audit)"),
    ("OPNsense - vpn", "OpenVPN logins and sessions"),
    ("OPNsense - dhcp", "DHCP leases (IP -> MAC -> hostname)"),
    ("OPNsense - dns", "Unbound DNS queries"),
    ("SIEM - Threat intel hits", "Any message that matched a threat-intel IOC"),
]


def ensure_streams():
    index_set = next(i["id"] for i in api("GET", "/api/system/indices/index_sets")["index_sets"] if i["default"])
    existing = {s["title"]: s for s in api("GET", "/api/streams")["streams"]}
    ids = {}
    for title, desc in STREAMS:
        if title in existing:
            ids[title] = existing[title]["id"]
            log("stream", title, False)
            continue
        # Graylog 7 wraps new entities in {"entity": ...} (optional "share_request")
        sid = api("POST", "/api/streams", {"entity": {
            "title": title, "description": desc, "rules": [], "matching_type": "AND",
            "remove_matches_from_default_stream": False, "index_set_id": index_set}})["stream_id"]
        api("POST", f"/api/streams/{sid}/resume")
        ids[title] = sid
        log("stream", title, True)
    return ids


# --- notifications ----------------------------------------------------------

EMAIL_BODY = """[SIEM POC] ${event_definition_title}
Priority : ${event.priority}
Time     : ${event.timestamp}
Message  : ${event.message}
Group by : ${foreach event.group_by_fields field}${field.key}=${field.value} ${end}

${if backlog}Last related log lines:
${foreach backlog message}- ${message.timestamp} | ${message.source} | ${message.message}
${end}${end}
Open Graylog: http://localhost:9000/alerts
"""


def ensure_notifications():
    allow = api("GET", "/api/system/urlallowlist")
    if not any(e["value"] == WEBHOOK_URL for e in allow["entries"]):
        allow["entries"].append({"id": "siem-poc-webhook", "title": "SIEM POC webhook", "type": "literal",
                                 "value": WEBHOOK_URL})
        api("PUT", "/api/system/urlallowlist", allow)
    existing = {n["title"]: n["id"] for n in api("GET", "/api/events/notifications?per_page=100")["notifications"]}
    wanted = {
        "Email - SOC team": {"type": "email-notification-v1", "sender": "",
                             "subject": "[SIEM][P${event.priority}] ${event_definition_title}",
                             "body_template": EMAIL_BODY, "html_body_template": "",
                             "email_recipients": [ALERT_EMAIL_TO], "user_recipients": [],
                             "time_zone": "Asia/Bangkok", "include_event_procedure": False},
        "Webhook - chat/ticketing": {"type": "http-notification-v1", "url": WEBHOOK_URL,
                                     "skip_tls_verification": False, "basic_auth": None, "api_key": None,
                                     "api_secret": None},
    }
    for title, cfg in wanted.items():
        if title not in existing:
            existing[title] = api("POST", "/api/events/notifications",
                                  {"entity": {"title": title, "description": "SIEM POC", "config": cfg}})["id"]
            log("notification", title, True)
        else:
            log("notification", title, False)
    return existing["Email - SOC team"], existing["Webhook - chat/ticketing"]


# --- alerts (event definitions) --------------------------------------------

LOW, MEDIUM, HIGH = 1, 2, 3


def alert(title, desc, priority, query, streams, window_min=5, group_by=(), series=None, cond=None):
    """series=("count", None) or ("card", "dst_port"); cond=(">=", 15)."""
    cfg = {"type": "aggregation-v1", "query": query, "query_parameters": [], "filters": [],
           "streams": streams, "group_by": list(group_by),
           "search_within_ms": window_min * 60_000, "execute_every_ms": 60_000,
           "use_cron_scheduling": False, "event_limit": 100, "series": [], "conditions": None}
    if series:
        func, field = series
        sid = f"{func}-{field or ''}"
        cfg["series"] = [{"id": sid, "type": func, **({"field": field} if field else {})}]
        cfg["conditions"] = {"expression": {"expr": cond[0], "left": {"expr": "number-ref", "ref": sid},
                                            "right": {"expr": "number", "value": cond[1]}}}
    return {"title": title, "description": desc, "priority": priority, "config": cfg}


def ensure_alerts(streams, email_id, webhook_id):
    s = streams
    fw, ids, auth, conf, vpn, dns, ti = (s["OPNsense - firewall"], s["OPNsense - ids"], s["OPNsense - auth"],
                                         s["OPNsense - config"], s["OPNsense - vpn"], s["OPNsense - dns"],
                                         s["SIEM - Threat intel hits"])
    definitions = [
        alert("[NET-01] Port scan from single source",
              ">= 15 distinct destination ports blocked from one source within 1 minute.",
              HIGH, "fw_action:block", [fw], 1, ["src_ip", "src_zone"], ("card", "dst_port"), (">=", 15)),
        alert("[NET-02] Guest network trying to reach internal zones",
              "Segregation violation: Guest VLAN blocked >= 5 times towards Server/LAN/Management (ISO A.8.22).",
              HIGH, "src_zone:Guest AND fw_action:block AND dst_zone:(Server OR LAN\\-Office OR Management)",
              [fw], 5, ["src_ip", "src_zone"], ("count", None), (">=", 5)),
        alert("[IAM-01] Firewall GUI brute force",
              ">= 5 failed web GUI logins from the same source within 5 minutes.",
              HIGH, "event_type:gui_login_failure", [auth], 5, ["src_ip", "src_zone"], ("count", None), (">=", 5)),
        alert("[IAM-02] Firewall admin login from outside Management zone",
              "Privileged login to the firewall GUI from a non-management network (ISO A.8.2 / A.8.5).",
              MEDIUM, "event_type:gui_login_success AND NOT src_zone:Management", [auth], 5,
              ["user", "src_ip", "src_zone"], ("count", None), (">=", 1)),
        alert("[IAM-03] Firewall admin login after hours",
              "Successful firewall GUI login between 19:00 and 07:59 Asia/Bangkok.",
              MEDIUM, "event_type:gui_login_success AND (local_hour:>=19 OR local_hour:<8)", [auth], 5,
              ["user", "src_ip", "local_hour"], ("count", None), (">=", 1)),
        alert("[IAM-04] VPN brute force",
              ">= 5 failed VPN logins for the same user within 5 minutes.",
              HIGH, "event_type:vpn_auth_failure", [vpn], 5, ["vpn_user"], ("count", None), (">=", 5)),
        alert("[CHG-01] Firewall configuration changed",
              "Every firewall config change, with who/where (ISO A.8.9 / A.8.32 change evidence).",
              LOW, "event_type:config_change", [conf], 5,
              ["user", "src_ip", "changed_via"], ("count", None), (">=", 1)),
        alert("[THR-01] IDS high-severity alert",
              "Suricata alert with priority 1 (malware, exploit, C2).",
              HIGH, "ids_priority:1", [ids], 5,
              ["ids_signature", "src_ip", "dst_ip"], ("count", None), (">=", 1)),
        alert("[THR-02] Allowed traffic to/from threat-intel IOC",
              "Firewall PASSED a connection involving an IP on the threat-intel list.",
              HIGH, "event_category:firewall AND fw_action:pass", [ti], 5,
              ["src_ip", "dst_ip", "dst_port", "threat_category"], ("count", None), (">=", 1)),
        alert("[THR-03] DNS query to malicious domain",
              "Internal host resolved a domain on the threat-intel list (phishing / C2).",
              HIGH, "event_category:dns", [ti], 5,
              ["src_ip", "dns_query", "threat_category"], ("count", None), (">=", 1)),
        alert("[OPS-01] OPNsense log source silent",
              "No OPNsense logs for 5 minutes - logging failure or tampering (ISO A.8.15 / A.8.16).",
              HIGH, "event_source:opnsense", [DEFAULT_STREAM], 5, (), ("count", None), ("<", 1)),
    ]
    existing = {d["title"]: d for d in api("GET", "/api/events/definitions?per_page=200")["event_definitions"]}
    for d in definitions:
        notify = [{"notification_id": email_id}]
        if d["priority"] >= HIGH:
            notify.append({"notification_id": webhook_id})
        d.update({"alert": True, "field_spec": {}, "key_spec": [],
                  "notification_settings": {"grace_period_ms": 300_000, "backlog_size": 5},
                  "notifications": notify,
                  "storage": [{"type": "persist-to-streams-v1", "streams": [EVENTS_STREAM]}]})
        if d["title"] in existing:
            did = existing[d["title"]]["id"]
            api("PUT", f"/api/events/definitions/{did}?schedule=true", {**d, "id": did})
            print(f"  ~ updated  alert: {d['title']}")
        else:
            api("POST", "/api/events/definitions?schedule=true", {"entity": d})
            log("alert", d["title"], True)


def main():
    print(f"Provisioning Graylog at {URL}")
    wait_for_graylog()
    print("inputs:");        ensure_inputs()
    print("lookup tables:"); ensure_lookups()
    print("streams:");       streams = ensure_streams()
    print("pipeline:");      ensure_pipeline()
    print("notifications:"); email_id, webhook_id = ensure_notifications()
    print("alerts:");        ensure_alerts(streams, email_id, webhook_id)
    print("done.")


if __name__ == "__main__":
    main()
