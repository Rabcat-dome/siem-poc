#!/usr/bin/env python3
"""Provision Graylog for the OPNsense SIEM POC via its REST API.

Creates (idempotently, matched by title/name):
  retention -> inputs -> lookup tables -> streams -> pipeline rules + pipeline -> notifications
  -> alerts -> dashboards -> users (RBAC)

Safe to re-run: existing objects are left as they are, except pipeline rules,
the pipeline and alerts, which are updated so edits in this repo apply. Dashboards
are replaced only when their definition in this file has changed.
"""
import base64
import glob
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid

URL = os.getenv("GRAYLOG_URL", "http://localhost:9000").rstrip("/")
AUTH = base64.b64encode(f"{os.getenv('GRAYLOG_USER', 'admin')}:{os.getenv('GRAYLOG_PASSWORD', 'admin')}".encode()).decode()
CONF_DIR = os.getenv("GRAYLOG_CONF_DIR", "/graylog")
# production serves Graylog over HTTPS with our private CA (docker-compose.prod.yml)
TLS = ssl.create_default_context(cafile=os.environ["GRAYLOG_CA_FILE"]) if os.getenv("GRAYLOG_CA_FILE") else None
LOOKUP_DIR_IN_GRAYLOG = "/usr/share/graylog/data/lookup"
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "soc-team@example.local")
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "http://webhook:8088/alert")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "1514"))
LOG_RETENTION_DAYS = int(os.getenv("LOG_RETENTION_DAYS", "90"))      # Q2 / NFR-01
EVENT_RETENTION_DAYS = int(os.getenv("EVENT_RETENTION_DAYS", "365"))  # alert history = incident evidence
IT_ANALYST_PASSWORD = os.getenv("IT_ANALYST_PASSWORD", "")
LOG_ADMIN_PASSWORD = os.getenv("LOG_ADMIN_PASSWORD", "")
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
        with urllib.request.urlopen(req, timeout=30, context=TLS) as r:
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


# --- retention (index sets) -------------------------------------------------

INDEX_SET_FIELDS = ("id", "title", "description", "writable", "shards", "replicas", "rotation_strategy_class",
                    "rotation_strategy", "retention_strategy_class", "retention_strategy", "index_analyzer",
                    "index_optimization_max_num_segments", "index_optimization_disabled",
                    "field_type_refresh_interval", "field_type_profile", "data_tiering", "use_legacy_rotation")


def ensure_retention():
    """Hot-only data tiering: an index is deleted once all of its data is older than `days` (+5 day slack)."""
    wanted = {"Default index set": LOG_RETENTION_DAYS, "Events": EVENT_RETENTION_DAYS}
    for index_set in api("GET", "/api/system/indices/index_sets")["index_sets"]:
        days = wanted.get(index_set["title"])
        if days is None:
            continue
        lifetime = {"index_lifetime_min": f"P{days}D", "index_lifetime_max": f"P{days + 5}D"}
        if index_set.get("data_tiering", {}).get("index_lifetime_min") == lifetime["index_lifetime_min"]:
            print(f"  = exists  retention: {index_set['title']} keeps {days} days")
            continue
        body = {k: index_set[k] for k in INDEX_SET_FIELDS if k in index_set}
        body["data_tiering"] = {"type": "hot_only", **lifetime}
        body["rotation_strategy"] = {**index_set["rotation_strategy"], **lifetime}
        api("PUT", f"/api/system/indices/index_sets/{index_set['id']}", body)
        print(f"  ~ updated  retention: {index_set['title']} keeps {days} days")


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
    ("fw-rule-tag", "fw_rules.csv", "rid", "tag", False, None),
    ("threat-intel-ip", "threat_intel_ip.csv", "ip", "category", False, None),
    ("threat-intel-domain", "threat_intel_domain.csv", "domain", "category", False, None),
    # web filtering: same domains as the Unbound blocklists, with the company policy per category
    ("web-category", "web_categories.csv", "domain", "category", False, None),
    ("web-policy", "web_categories.csv", "domain", "policy", False, None),
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
    ("SIEM - Web filtering", "Categorised DNS queries and attempts to bypass the DNS filter"),
    ("SIEM - Log integrity", "Results of the SHA-256 manifest checks on archived logs (tools/log_manifest.py)"),
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
    """-> (email id, webhook id or None). An empty WEBHOOK_URL means e-mail only (Q4)."""
    allow = api("GET", "/api/system/urlallowlist")
    if WEBHOOK_URL and not any(e["value"] == WEBHOOK_URL for e in allow["entries"]):
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
    if not WEBHOOK_URL:
        del wanted["Webhook - chat/ticketing"]
    for title, cfg in wanted.items():
        if title not in existing:
            existing[title] = api("POST", "/api/events/notifications",
                                  {"entity": {"title": title, "description": "SIEM POC", "config": cfg}})["id"]
            log("notification", title, True)
        else:
            log("notification", title, False)
    return existing["Email - SOC team"], existing.get("Webhook - chat/ticketing") if WEBHOOK_URL else None


# --- alerts (event definitions) --------------------------------------------

LOW, MEDIUM, HIGH = 1, 2, 3


def alert(title, desc, priority, query, streams, window_min=5, group_by=(), series=None, cond=None, grace_min=5):
    """series=("count", None) or ("card", "dst_port"); cond=(">=", 15).
    grace_min: after a notification, stay quiet this long for the same alert."""
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
    return {"title": title, "description": desc, "priority": priority, "config": cfg,
            "notification_settings": {"grace_period_ms": grace_min * 60_000, "backlog_size": 5}}


def ensure_alerts(streams, email_id, webhook_id):
    s = streams
    fw, ids, auth, conf, vpn, ti, web, integrity = (
        s["OPNsense - firewall"], s["OPNsense - ids"], s["OPNsense - auth"], s["OPNsense - config"],
        s["OPNsense - vpn"], s["SIEM - Threat intel hits"], s["SIEM - Web filtering"], s["SIEM - Log integrity"])
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
        alert("[WEB-01] Repeated access to blocked web category",
              ">= 10 DNS queries to blocked categories (gambling, adult, drugs, p2p, malware) from one host "
              "within 1 hour - policy violation or infected host (ISO A.8.23).",
              MEDIUM, "web_policy:block", [web], 60, ["src_ip", "src_zone"], ("count", None), (">=", 10),
              grace_min=60),
        alert("[WEB-02] Attempt to bypass DNS filtering",
              ">= 3 blocked connections to DoT (853), outside DNS (53) or DoH resolvers from one host "
              "within 5 minutes (ISO A.8.23 / A.8.20).",
              MEDIUM, "fw_rule_tag:dns\\-bypass", [web], 5, ["src_ip", "src_zone"], ("count", None), (">=", 3),
              grace_min=60),
        alert("[OPS-01] OPNsense log source silent",
              "No OPNsense logs for 5 minutes - logging failure or tampering (ISO A.8.15 / A.8.16).",
              HIGH, "event_source:opnsense", [DEFAULT_STREAM], 5, (), ("count", None), ("<", 1)),
        alert("[OPS-02] Log archive integrity check failed",
              "tools/log_manifest.py verify found a modified or missing archive file - possible log tampering "
              "(ISO A.8.15 / A.5.28, NFR-11).",
              HIGH, "event_type:log_manifest_verify AND result:FAIL", [integrity], 5,
              ["source", "mismatch", "missing"], ("count", None), (">=", 1)),
    ]
    existing = {d["title"]: d for d in api("GET", "/api/events/definitions?per_page=200")["event_definitions"]}
    for d in definitions:
        notify = [{"notification_id": email_id}]
        if d["priority"] >= HIGH and webhook_id:
            notify.append({"notification_id": webhook_id})
        d.update({"alert": True, "field_spec": {}, "key_spec": [],
                  "notifications": notify,
                  "storage": [{"type": "persist-to-streams-v1", "streams": [EVENTS_STREAM]}]})
        if d["title"] in existing:
            did = existing[d["title"]]["id"]
            api("PUT", f"/api/events/definitions/{did}?schedule=true", {**d, "id": did})
            print(f"  ~ updated  alert: {d['title']}")
        else:
            api("POST", "/api/events/definitions?schedule=true", {"entity": d})
            log("alert", d["title"], True)


# --- dashboards (FR-11) -----------------------------------------------------

DAY = {"type": "relative", "range": 86400}  # every widget defaults to the last 24 hours
VIZ_CONFIG = {"bar": {"barmode": "stack", "axis_type": "linear", "axis_config": None},
              "numeric": {"trend": False, "trend_preference": "NEUTRAL"}}


def agg(title, query="", rows=(), cols=(), viz="table", streams=(), limit=10, w=6, h=4):
    """count() widget. rows/cols: the fields of one row/column pivot; rows=["timestamp"] = histogram."""
    return {"type": "aggregation", "title": title, "query": query, "rows": list(rows), "cols": list(cols),
            "viz": viz, "streams": list(streams), "limit": limit, "w": w, "h": h}


def number(title, query, streams):
    return agg(title, query, viz="numeric", streams=streams, w=3, h=2)


def messages(title, query, fields, streams, w=12, h=5):
    return {"type": "messages", "title": title, "query": query, "fields": ["timestamp", *fields],
            "streams": list(streams), "w": w, "h": h}


def dashboard_specs(s):
    """(title, summary, widgets); s maps stream title -> id."""
    fw, ids, auth, conf, vpn = (s[f"OPNsense - {n}"] for n in ("firewall", "ids", "auth", "config", "vpn"))
    ti, web, events = s["SIEM - Threat intel hits"], s["SIEM - Web filtering"], [EVENTS_STREAM]
    guest_to_internal = "src_zone:Guest AND fw_action:block AND dst_zone:(Server OR LAN\\-Office OR Management)"
    return [
        ("SIEM - Overview (management)", "Log volume, alerts, web policy violations and privileged activity", [
            number("Alerts", "", events),
            number("Firewall admin logins", "event_type:gui_login_success", [auth]),
            number("Failed admin logins", "event_type:gui_login_failure", [auth]),
            number("Firewall config changes", "event_type:config_change", [conf]),
            agg("Log volume by category", "event_source:opnsense", ["timestamp"], ["event_category"], "bar", w=12),
            agg("Alerts over time by priority (1 low, 2 medium, 3 high)", "", ["timestamp"], ["priority"], "bar",
                events),
            agg("Top alerts", "", ["event_definition_id"], streams=events, limit=15),
            agg("Top blocked web categories", "web_policy:block", ["web_category"], viz="pie", streams=[web]),
            agg("Admin logins and config changes by user", "event_type:(gui_login_success OR config_change)",
                ["user"], ["event_type"], streams=[auth, conf]),
        ]),
        ("SIEM - Firewall & network", "Passed vs blocked traffic, top blocked sources and ports, zone segregation", [
            agg("Blocked vs passed over time", "", ["timestamp"], ["fw_action"], "bar", [fw], w=12),
            agg("Top blocked sources", "fw_action:block", ["src_ip", "src_zone"], streams=[fw], limit=15),
            agg("Top blocked destination ports", "fw_action:block", ["dst_port", "protocol"], streams=[fw], limit=15),
            agg("Zone-to-zone matrix (rows: source zone, columns: destination zone)", "", ["src_zone"], ["dst_zone"],
                streams=[fw]),
            agg("Guest -> internal zones, blocked (ISO A.8.22)", guest_to_internal,
                ["src_ip", "dst_zone", "dst_ip", "dst_port"], streams=[fw], limit=15),
        ]),
        ("SIEM - Identity & admin", "Firewall GUI logins, VPN authentication failures and configuration changes", [
            agg("Firewall GUI logins over time", "event_type:(gui_login_success OR gui_login_failure)",
                ["timestamp"], ["event_type"], "bar", [auth], w=12),
            agg("Failed GUI logins by source", "event_type:gui_login_failure", ["src_ip", "src_zone", "user"],
                streams=[auth], limit=15),
            agg("VPN authentication failures by user", "event_type:vpn_auth_failure", ["vpn_user"],
                streams=[vpn], limit=15),
            messages("Recent firewall config changes", "event_type:config_change", ["user", "src_ip", "changed_via"],
                     [conf]),
        ]),
        ("SIEM - Web filtering & threat", "Web category policy, DNS filter bypass, IDS alerts and threat-intel hits", [
            agg("Blocked web categories", "web_policy:block", ["web_category"], viz="pie", streams=[web], w=4),
            agg("Top hosts querying blocked categories", "web_policy:block", ["src_ip", "src_host", "src_owner"],
                streams=[web], limit=15, w=8),
            agg("Monitored category usage", "web_policy:monitor", ["web_category"], viz="bar", streams=[web], w=4),
            agg("DNS filter bypass attempts by source (columns: port)", "fw_rule_tag:dns\\-bypass",
                ["src_ip", "src_host"], ["dst_port"], streams=[web], w=8),
            agg("IDS signatures", "", ["ids_signature", "ids_priority"], streams=[ids], limit=15),
            agg("Threat-intel hits by IOC", "", ["threat_ioc", "threat_category"], ["event_category"],
                streams=[ti], limit=15),
        ]),
    ]


def _uid(*parts):
    """Stable ids, so an unchanged definition always builds the same view."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "siem-poc/" + "/".join(parts)))


def _pivot(fields, limit):
    if fields == ["timestamp"]:
        return {"fields": fields, "type": "time", "config": {"interval": {"type": "auto", "scaling": 1.0}}}
    return {"fields": fields, "type": "values", "config": {"limit": limit, "skip_empty_values": False}}


def _widget(w, wid):
    """-> (view widget, search type), in the shape the web UI saves them."""
    common = {"timerange": DAY, "query": {"type": "elasticsearch", "query_string": w["query"]},
              "streams": w["streams"], "stream_categories": [], "filter": None, "filters": []}
    st = {**common, "id": _uid(wid, "search-type")}
    if w["type"] == "messages":
        cfg = {"fields": w["fields"], "show_message_row": False, "show_summary": False, "decorators": [],
               "sort": [{"type": "pivot", "field": "timestamp", "direction": "Descending"}]}
        st.update(type="messages", limit=150, offset=0, decorators=[], sort=[{"field": "timestamp", "order": "DESC"}])
    else:
        rows = [_pivot(w["rows"], w["limit"])] if w["rows"] else []
        cols = [_pivot(w["cols"], w["limit"])] if w["cols"] else []
        top_n = w["rows"] not in ([], ["timestamp"])
        sort = [{"type": "series", "field": "count()", "direction": "Descending"}] if top_n else []
        rollup = w["viz"] == "table" or not cols  # charts split by a column pivot get no "total" series
        cfg = {"row_pivots": rows, "column_pivots": cols, "sort": sort, "rollup": rollup,
               "series": [{"config": {"name": None, "thresholds": None}, "function": "count()"}],
               "visualization": w["viz"], "visualization_config": VIZ_CONFIG.get(w["viz"]),
               "formatting_settings": None, "event_annotation": False, "units": {}}
        st.update(type="pivot", name="chart", rollup=rollup, sort=sort, series=[{"id": "count()", "type": "count"}],
                  row_groups=[{"type": p["type"], "fields": p["fields"], **p["config"]} for p in rows],
                  column_groups=[{"type": p["type"], "fields": p["fields"], **p["config"]} for p in cols])
    return {**common, "id": wid, "type": w["type"], "config": cfg, "description": None, "context": None}, st


def _layout(widgets):
    """Flow widgets left to right over the 12-column grid."""
    positions, row, col, row_height = {}, 1, 1, 0
    for wid, w in widgets:
        if col + w["w"] > 13:
            row, col, row_height = row + row_height, 1, 0
        positions[wid] = {"col": col, "row": row, "height": w["h"], "width": w["w"]}
        col, row_height = col + w["w"], max(row_height, w["h"])
    return positions


def ensure_dashboards():
    streams = {s["title"]: s["id"] for s in api("GET", "/api/streams")["streams"]}
    existing = {v["title"]: v for v in api("GET", "/api/views?per_page=200")["views"] if v["type"] == "DASHBOARD"}
    for title, summary, widgets in dashboard_specs(streams):
        qid = _uid(title)
        ids = [(_uid(title, w["title"]), w) for w in widgets]
        built = [_widget(w, wid) for wid, w in ids]
        state = {"selected_fields": None, "static_message_list_id": None,
                 "titles": {"tab": {"title": title.split(" - ", 1)[-1]}, "widget": {wid: w["title"] for wid, w in ids}},
                 "widgets": [widget for widget, _ in built],
                 "widget_mapping": {widget["id"]: [st["id"]] for widget, st in built},
                 "positions": _layout(ids), "formatting": {"highlighting": []},
                 "display_mode_settings": {"positions": {}}}
        query = {"id": qid, "query": {"type": "elasticsearch", "query_string": ""}, "timerange": DAY,
                 "filter": None, "filters": [], "search_types": [st for _, st in built]}
        # fingerprint of the definition, kept in the view's properties: unchanged -> leave UI edits alone
        tag = "siem-poc-spec:" + hashlib.sha256(json.dumps([state, query], sort_keys=True).encode()).hexdigest()[:16]
        current = existing.get(title)
        if current and tag in current.get("properties", []):
            log("dashboard", title, False)
            continue
        # a view points at a separate search holding the widgets' queries; like the UI, save a new one each time
        # (Graylog removes searches no view references). Views, unlike searches, are wrapped in {"entity": ...}.
        search_id = api("POST", "/api/views/search", {"queries": [query], "parameters": []})["id"]
        view = {"type": "DASHBOARD", "title": title, "summary": summary,
                "description": f"{summary}. Provisioned by provisioner/provision.py (FR-11); UI edits are replaced "
                               "when the definition there changes.",
                "search_id": search_id, "properties": [tag], "requires": {}, "state": {qid: state}}
        if current:
            api("PUT", f"/api/views/{current['id']}", {"entity": {**view, "id": current["id"]}})
            print(f"  ~ updated  dashboard: {title}")
        else:
            api("POST", "/api/views", {"entity": view})
            log("dashboard", f"{title} ({len(widgets)} widgets)", True)


# --- users / RBAC (Q16) -----------------------------------------------------

USERS = [
    # username, full name, password, built-in roles, stream access
    ("it-analyst", "IT Analyst", IT_ANALYST_PASSWORD,
     ["Reader", "Alerts Manager", "Pipelines Manager", "Dashboard Creator", "Views Manager"], "view"),
    # break-glass: credentials held by management / ISMS manager, every use is recorded
    ("log-admin", "Log Administrator (break-glass)", LOG_ADMIN_PASSWORD, ["Admin"], None),
]


def share_with(entity_grn, user_id, capability):
    """Add one grantee to an entity's shares without dropping the existing ones."""
    current = api("POST", f"/api/authz/shares/entities/{entity_grn}/prepare", {}).get("selected_grantee_capabilities", {})
    grantee = f"grn::::user:{user_id}"
    if current.get(grantee) == capability:
        return
    api("POST", f"/api/authz/shares/entities/{entity_grn}", {"selected_grantee_capabilities": {**current, grantee: capability}})


def ensure_users():
    existing = {u["username"]: u for u in api("GET", "/api/users")["users"]}
    stream_ids = [s["id"] for s in api("GET", "/api/streams")["streams"]]
    for username, full_name, password, roles, stream_capability in USERS:
        if username not in existing:
            if not password:
                print(f"  ! skipped  user: {username} (set its password in .env to create it)")
                continue
            first, _, last = full_name.partition(" ")
            api("POST", "/api/users", {"username": username, "first_name": first, "last_name": last or "-",
                                       "email": f"{username}@example.local", "password": password,
                                       "roles": roles, "permissions": [], "timezone": "Asia/Bangkok",
                                       "session_timeout_ms": 8 * 3600_000})
            log("user", f"{username} ({', '.join(roles)})", True)
        else:
            log("user", f"{username} ({', '.join(roles)})", False)
        if stream_capability:
            user_id = api("GET", f"/api/users/{username}")["id"]
            for sid in stream_ids:
                share_with(f"grn::::stream:{sid}", user_id, stream_capability)


def main():
    print(f"Provisioning Graylog at {URL}")
    wait_for_graylog()
    print("retention:");     ensure_retention()
    print("inputs:");        ensure_inputs()
    from hardening import ensure_tls_input; ensure_tls_input()  # syslog over TLS 6514 (NFR-05)
    print("lookup tables:"); ensure_lookups()
    print("streams:");       streams = ensure_streams()
    print("pipeline:");      ensure_pipeline()
    print("notifications:"); email_id, webhook_id = ensure_notifications()
    print("alerts:");        ensure_alerts(streams, email_id, webhook_id)
    print("dashboards:");    ensure_dashboards()
    print("users:");         ensure_users()
    print("done.")


if __name__ == "__main__":
    main()
