#!/usr/bin/env python3
"""Tiny webhook receiver standing in for LINE / MS Teams / ticketing / SOAR.

Graylog HTTP notifications POST the event JSON to /alert; GET / shows the
latest alerts so you can watch them arrive during the POC.
"""
import html
import json
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ALERTS = deque(maxlen=200)
PRIORITY = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0)
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            payload = {"raw": body.decode(errors="replace")}
        event = payload.get("event", {})
        alert = {
            "received": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "title": payload.get("event_definition_title", "?"),
            "priority": PRIORITY.get(event.get("priority"), event.get("priority")),
            "message": event.get("message", ""),
            "group_by": event.get("group_by_fields", {}),
            "backlog": len(payload.get("backlog", [])),
        }
        ALERTS.appendleft(alert)
        print(f"ALERT [{alert['priority']}] {alert['title']} :: {alert['message']}", flush=True)
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        if self.path == "/api/alerts":
            data, ctype = json.dumps(list(ALERTS), ensure_ascii=False).encode(), "application/json"
        else:
            rows = "".join(
                f"<tr class='p{html.escape(str(a['priority']))}'><td>{a['received']}</td>"
                f"<td>{html.escape(str(a['priority']))}</td><td>{html.escape(a['title'])}</td>"
                f"<td>{html.escape(a['message'])}</td><td>{html.escape(json.dumps(a['group_by']))}</td></tr>"
                for a in ALERTS) or "<tr><td colspan=5>No alerts yet</td></tr>"
            data = (f"""<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=5>
<title>Webhook alerts</title><style>
body{{font:14px system-ui;margin:24px;background:#fafafa}} table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}}
.pHIGH td:nth-child(2),.pCRITICAL td:nth-child(2){{color:#b00020;font-weight:600}}
</style><h2>Alerts received by webhook ({len(ALERTS)})</h2>
<p>Stand-in for LINE / MS Teams / ticketing. Auto-refresh every 5s.</p>
<table><tr><th>Received</th><th>Priority</th><th>Alert</th><th>Message</th><th>Group by</th></tr>{rows}</table>""").encode()
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("webhook receiver on :8088", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8088), Handler).serve_forever()
