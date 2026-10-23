"""Production-hardening provisioning steps (kept apart from provision.py).

ensure_tls_input(): syslog over TLS on 6514 (NFR-05). Idempotent, matched by title.
The input is only created when the certificate and key are visible on the
provisioner side (compose mounts ./tls at /tls), otherwise it is skipped with a
hint, so the POC still provisions cleanly without certificates.

  TLS_CONTAINER_DIR  where the Graylog container sees the files (default /usr/share/graylog/data/tls)
  TLS_HOST_DIR       where this process sees the same files     (default /tls)
  SYSLOG_TLS_PORT    listen port inside the container            (default 6514)
"""
import os

TLS_CONTAINER_DIR = os.getenv("TLS_CONTAINER_DIR", "/usr/share/graylog/data/tls")
TLS_HOST_DIR = os.getenv("TLS_HOST_DIR", "/tls")
SYSLOG_TLS_PORT = int(os.getenv("SYSLOG_TLS_PORT", "6514"))
CERT_NAME, KEY_NAME = "server.crt", "server.key"


def ensure_tls_input(container_dir=None, host_dir=None, port=None):
    from provision import api, log  # imported late: provision.py owns the API helpers

    container_dir = (container_dir or TLS_CONTAINER_DIR).rstrip("/")
    host_dir = host_dir or TLS_HOST_DIR
    port = port or SYSLOG_TLS_PORT
    title = f"OPNsense Syslog TLS {port}"

    missing = [n for n in (CERT_NAME, KEY_NAME) if not os.path.isfile(os.path.join(host_dir, n))]
    if missing:
        print(f"  - skipped input: {title} ({', '.join(missing)} not found in {host_dir}; "
              f"run tools/gen_tls_certs.sh <siem-fqdn> <siem-ip>, then re-run the provisioner)")
        return

    existing = {i["title"]: i for i in api("GET", "/api/system/inputs")["inputs"]}
    if title in existing:
        input_id = existing[title]["id"]
        log("input", title, False)
        states = {s["id"]: s["state"] for s in api("GET", "/api/system/inputstates")["states"]}
        if states.get(input_id) not in ("RUNNING", "STARTING"):
            api("PUT", f"/api/system/inputstates/{input_id}")
        return

    cfg = {"bind_address": "0.0.0.0", "port": port, "recv_buffer_size": 1048576,
           "number_worker_threads": 2, "override_source": None, "force_rdns": False,
           "allow_override_date": True, "store_full_message": True,
           "expand_structured_data": False, "timezone": "Asia/Bangkok",
           "tls_enable": True, "tls_cert_file": f"{container_dir}/{CERT_NAME}",
           "tls_key_file": f"{container_dir}/{KEY_NAME}", "tls_key_password": "",
           "tls_client_auth": "disabled", "tcp_keepalive": True,
           "use_null_delimiter": False, "max_message_size": 2097152}
    api("POST", "/api/system/inputs", {"title": title, "type": "org.graylog2.inputs.syslog.tcp.SyslogTCPInput",
                                       "global": True, "configuration": cfg})
    log("input", title, True)  # new inputs start on their own
