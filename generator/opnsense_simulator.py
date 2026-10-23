#!/usr/bin/env python3
"""OPNsense log simulator for the SIEM POC.

Emits RFC5424 syslog shaped like a real OPNsense box (filterlog, suricata,
audit, openvpn, dhcpd, unbound) so the Graylog pipeline rules in this repo
work unchanged when a real firewall is pointed at the same input.

It also plays a managed switch and a Wi-Fi AP (RFC3164, as most network gear
sends it) until the real models are known (Q9): the switch speaks Cisco
IOS-style mnemonics (%LINK-3-UPDOWN ...) and the AP hostapd + dropbear, which
most Linux-based APs use. Blocked DNS answers use Unbound's log-local-actions
line. All three formats are assumptions to check against the real devices.

Every INTERVAL_SECONDS it sends a batch of normal traffic, and with
probability SCENARIO_RATE it also plays one attack scenario so the alerts
in Graylog have something to fire on.

  python opnsense_simulator.py                    # continuous mode
  python opnsense_simulator.py --play all         # fire every scenario once, then exit
  python opnsense_simulator.py --play port_scan c2_beacon
"""
import os
import random
import socket
import sys
import time
from datetime import datetime, timedelta, timezone

SYSLOG_HOST = os.getenv("SYSLOG_HOST", "graylog")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "1514"))
SYSLOG_PROTO = os.getenv("SYSLOG_PROTO", "udp").lower()
INTERVAL = float(os.getenv("INTERVAL_SECONDS", "5"))
SCENARIO_RATE = float(os.getenv("SCENARIO_RATE", "0.25"))
FW_HOSTNAME = os.getenv("FW_HOSTNAME", "opnsense.poc.local")
SWITCH_HOSTNAME = os.getenv("SWITCH_HOSTNAME", "sw-core01")
AP_HOSTNAME = os.getenv("AP_HOSTNAME", "ap-office01")
SIEM_HOSTNAME = os.getenv("SIEM_HOSTNAME", "siem01")  # results of the SIEM host's own jobs (disk, manifest)
BKK = timezone(timedelta(hours=7))  # RFC3164 has no zone; the Graylog input reads it as Asia/Bangkok

# --- Simulated company network (documentation IP ranges only) -------------
WAN_IP = "203.0.113.10"
LAN_GW, SRV_GW, GUEST_GW, MGMT_GW = "192.168.10.1", "192.168.20.1", "192.168.30.1", "192.168.99.1"
IFACE = {"wan": "igb0", "lan": "igb1", "srv": "igb1_vlan20", "guest": "igb1_vlan30",
         "mgmt": "igb1_vlan99", "vpn": "ovpns1"}

LAN_CLIENTS = [
    ("192.168.10.21", "LT-SOMCHAI", "3c:22:fb:10:00:21"),
    ("192.168.10.22", "LT-SUDA", "3c:22:fb:10:00:22"),
    ("192.168.10.23", "LT-ANAN", "3c:22:fb:10:00:23"),
    ("192.168.10.24", "DT-RECEPTION", "3c:22:fb:10:00:24"),
    ("192.168.10.25", "LT-NARIN", "3c:22:fb:10:00:25"),
]
GUEST_CLIENTS = [
    ("192.168.30.51", "iPhone-guest", "a4:83:e7:30:00:51"),
    ("192.168.30.55", "UNKNOWN-PC", "00:0c:29:30:00:55"),
]
SERVERS = {"ad": "192.168.20.10", "file": "192.168.20.11", "erp": "192.168.20.12", "web": "192.168.20.13"}
ADMIN_WS = "192.168.99.10"
VPN_USERS = ["somchai.k", "suda.p", "narin.t"]
# devices that are not in assets.csv: a personal laptop on the office LAN and a Raspberry Pi on a switch port
ROGUE_LAPTOP = ("192.168.10.150", "MacBook-Pro", "f0:18:98:5a:3c:71")
ROGUE_PI_MAC = "b827.eb12.3456"  # Cisco notation, the pipeline turns it into b8:27:eb:12:34:56

# switch access ports per office desk, and the AP radios (must match graylog/lookup/wifi_ssids.csv)
SWITCH_PORTS = [f"GigabitEthernet1/0/{n}" for n in range(1, 17)]
WIFI_STAFF, WIFI_GUEST = ["wlan0", "wlan1"], "wlan0-1"

BENIGN_DOMAINS = ["www.google.com", "outlook.office365.com", "teams.microsoft.com", "line.me",
                  "www.facebook.com", "github.com", "api.ipify.org", "www.bot.or.th", "s3.amazonaws.com",
                  # allowed but monitored categories (social, streaming, cloud storage) - see web_categories.csv
                  "www.youtube.com", "www.tiktok.com", "www.instagram.com", "www.netflix.com", "drive.google.com"]
# blocked categories (gambling, adult, drugs, p2p) - must match graylog/lookup/web_categories.csv
BLOCKED_DOMAINS = ["thaicasino-bet.example", "www.slot-888.example", "adult-videos.example",
                   "drugs-shop.example", "torrent-tracker.example", "piratebay-mirror.example"]
# public resolvers people use to dodge the company DNS filter
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]
BENIGN_IPS = ["142.250.198.4", "52.97.146.162", "13.107.42.14", "147.92.146.52",
              "157.240.7.35", "140.82.112.4", "52.219.168.6"]
INTERNET_NOISE_SRC = ["198.51.100.23", "198.51.100.41", "192.0.2.77", "203.0.113.150", "192.0.2.13"]

# These three also live in graylog/lookup/threat_intel_*.csv
C2_IP, SCANNER_IP, BRUTE_IP = "198.51.100.66", "192.0.2.200", "203.0.113.77"
C2_DOMAIN, PHISH_DOMAIN = "cdn-update.malicious-c2.example", "login-microsoft-verify.example"

# rule label (rid) -> must match graylog/lookup/fw_rules.csv
RULES = {
    "default_deny": (5, "02f4bab031b57d1e30553ce08e0ec131"),
    "allow_lan_web": (70, "5708f9e9520b4894ab4d6f4d5680be5b"),
    "allow_lan_dns": (71, "ddcd8235e5f95d273806f2581f894e11"),
    "allow_guest_web": (80, "516029da64d14f0264da64dc1bc48133"),
    "block_guest_internal": (79, "d2c341112bd834d886d17c1de82e163e"),
    "allow_vpn_servers": (90, "96f5c0b74e022e0b375c24619797b391"),
    "nat_web01_https": (60, "eb6626d0c4b46f3a0eeb127e5b61a10f"),
    "allow_mgmt_gui": (95, "af86d0924bb78bc5d8a2af2d2ce9cc33"),
    "block_dot": (81, "ac87eb2b3711486a4c03407afdd88ca1"),
    "block_ext_dns": (82, "03fe13e5c8ecd0709616f808ff1ef77d"),
    "block_doh": (83, "9ea229df30c0603a9175d5a88b0344e3"),
}

# syslog facility codes
LOCAL0, AUTH, DAEMON, AUTHPRIV, LOCAL5, LOCAL7 = 16, 4, 3, 10, 21, 23
SEV_ALERT, SEV_CRIT, SEV_ERR, SEV_WARNING, SEV_NOTICE, SEV_INFO = 1, 2, 3, 4, 5, 6


class Sender:
    def __init__(self):
        self.seq = 0
        self.sock = None

    def _connect(self):
        if SYSLOG_PROTO == "tcp":
            self.sock = socket.create_connection((SYSLOG_HOST, SYSLOG_PORT), timeout=5)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, app, msg, facility=LOCAL0, severity=SEV_INFO, host=FW_HOSTNAME):
        self.seq += 1
        ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        pid = {"filterlog": 61531, "suricata": 30212, "audit": 4410, "openvpn_server1": 7731,
               "dhcpd": 2210, "unbound": 50443}.get(app, 1000)
        line = (f"<{facility * 8 + severity}>1 {ts} {host} {app} {pid} - "
                f'[meta sequenceId="{self.seq}"] {msg}')
        self._write(line.encode())

    def send3164(self, host, msg, facility, severity):
        """BSD syslog, the way switches and APs send it: <pri>Mmm dd hh:mm:ss host msg"""
        now = datetime.now(BKK)
        self._write(f"<{facility * 8 + severity}>{now:%b} {now.day:>2} {now:%H:%M:%S} {host} {msg}".encode())

    def _write(self, data):
        try:
            if self.sock is None:
                self._connect()
            if SYSLOG_PROTO == "tcp":
                self.sock.sendall(data + b"\n")
            else:
                self.sock.sendto(data, (SYSLOG_HOST, SYSLOG_PORT))
        except OSError as e:
            print(f"send failed ({e}); will retry next tick", flush=True)
            self.sock = None


out = Sender()


# --- Log line builders (formats follow OPNsense/pf, Suricata, ISC dhcpd, Unbound) ---

def filterlog(rule, iface, action, direction, proto, src, dst, sport=None, dport=None):
    nr, rid = RULES[rule]
    protonum = {"tcp": 6, "udp": 17, "icmp": 1}[proto]
    length = random.randint(40, 1500)
    flags = "DF" if proto == "tcp" else "none"
    head = (f"{nr},,,{rid},{iface},match,{action},{direction},4,0x0,,{random.randint(48, 128)},"
            f"{random.randint(1, 65535)},0,{flags},{protonum},{proto},{length},{src},{dst},")
    if proto == "tcp":
        tail = f"{sport},{dport},0,S,{random.randint(10**8, 4 * 10**9)},,64240,,mss;nop;wscale;sackOK;TS"
    elif proto == "udp":
        tail = f"{sport},{dport},{length - 28}"
    else:
        tail = f"request,{random.randint(1, 65535)},{random.randint(1, 100)}"
    out.send("filterlog", head + tail, LOCAL0, SEV_INFO)


def suricata(sid, signature, classification, priority, proto, src, sport, dst, dport):
    out.send("suricata",
             f"[1:{sid}:3] {signature} [Classification: {classification}] [Priority: {priority}] "
             f"{{{proto}}} {src}:{sport} -> {dst}:{dport}",
             LOCAL5, SEV_ALERT if priority == 1 else SEV_WARNING)


def gui_login(user, src, ok):
    if ok:
        out.send("audit", f"/index.php: Successful login for user '{user}' from: {src}", AUTH, SEV_NOTICE)
    else:
        out.send("audit", f"/index.php: Web GUI authentication error for user '{user}' from: {src}",
                 AUTH, SEV_WARNING)


def config_change(user, src, page):
    backup = f"/conf/backup/config-{time.time():.4f}.xml"
    out.send("audit", f"user {user}@{src} changed configuration to {backup} in {page}", AUTH, SEV_NOTICE)


def vpn_login(user, public_ip, ok):
    port = random.randint(30000, 65000)
    if ok:
        out.send("openvpn_server1", f"user '{user}' authenticated using 'Local Database'", DAEMON, SEV_NOTICE)
        vpn_ip = f"10.8.0.{6 + VPN_USERS.index(user) * 4 if user in VPN_USERS else random.randint(50, 99)}"
        out.send("openvpn_server1",
                 f"{user}/{public_ip}:{port} MULTI_sva: pool returned IPv4={vpn_ip}, IPv6=(Not enabled)",
                 DAEMON, SEV_NOTICE)
        return vpn_ip
    out.send("openvpn_server1",
             f"{public_ip}:{port} TLS Auth Error: Auth Username/Password verification failed for peer",
             DAEMON, SEV_WARNING)
    out.send("openvpn_server1", f"user '{user}' could not authenticate.", DAEMON, SEV_WARNING)
    return None


def dhcp_ack(ip, host, mac, iface):
    out.send("dhcpd", f"DHCPACK on {ip} to {mac} ({host}) via {iface}", DAEMON, SEV_INFO)


def dns_query(client, domain, qtype="A"):
    out.send("unbound", f"[50443:0] info: {client} {domain}. {qtype} IN", DAEMON, SEV_INFO)


def dns_blocked(client, domain, qtype="A"):
    # log-queries logs the question, log-local-actions the blocklist answer (0.0.0.0 = always_null)
    dns_query(client, domain, qtype)
    zone = domain.removeprefix("www.")
    out.send("unbound", f"[50443:0] info: {zone}. always_null {client}@{eport()} {domain}. {qtype} IN",
             DAEMON, SEV_INFO)


# --- the SIEM host's scheduled jobs (same lines as tools/disk_check.py and tools/log_manifest.py) ---

def disk_check(used_pct):
    result = "WARN" if used_pct >= 75 else "PASS"
    out.send("disk-check", f"action=disk_check path=/var/lib/docker used_pct={used_pct} "
                           f"free_gb={500 * (100 - used_pct) / 100:.1f} total_gb=500.0 warn_pct=75 result={result}",
             13, SEV_WARNING if result == "WARN" else SEV_INFO, host=SIEM_HOSTNAME)


def manifest(action, failed=False):
    if action == "create":
        msg = f"action=create new_files={random.randint(20, 40)} manifest=manifest-{datetime.now(BKK):%Y%m%d-%H%M%S}.sha256"
    else:
        msg = (f"action=verify result={'FAIL' if failed else 'PASS'} ok={random.randint(600, 900)} "
               f"mismatch={1 if failed else 0} missing=0 unlisted=0")
    out.send("log-manifest", msg, 13, SEV_ERR if failed else SEV_INFO, host=SIEM_HOSTNAME)


# --- switch (Cisco IOS-style) and Wi-Fi AP (hostapd / dropbear) ------------

def switch_link(port, state):
    out.send3164(SWITCH_HOSTNAME, f"%LINK-3-UPDOWN: Interface {port}, changed state to {state}", LOCAL7, SEV_ERR)


def switch_port_security(mac_dotted, port):
    out.send3164(SWITCH_HOSTNAME, "%PORT_SECURITY-2-PSECURE_VIOLATION: Security violation occurred, "
                                  f"caused by MAC address {mac_dotted} on port {port}.", LOCAL7, SEV_CRIT)


def switch_login(user, src, ok):
    at = datetime.now(BKK).strftime("%H:%M:%S ICT %a %b %d %Y")
    if ok:
        out.send3164(SWITCH_HOSTNAME, f"%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: {user}] [Source: {src}] "
                                      f"[localport: 22] at {at}", LOCAL7, SEV_NOTICE)
    else:
        out.send3164(SWITCH_HOSTNAME, f"%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: {user}] [Source: {src}] "
                                      f"[localport: 22] [Reason: Login Authentication Failed] at {at}",
                     LOCAL7, SEV_WARNING)


def switch_config(user, src):
    out.send3164(SWITCH_HOSTNAME, f"%SYS-5-CONFIG_I: Configured from console by {user} on vty0 ({src})",
                 LOCAL7, SEV_NOTICE)


def ap_station(iface, event, mac):
    out.send3164(AP_HOSTNAME, f"hostapd: {iface}: AP-STA-{event} {mac}", DAEMON, SEV_INFO)


def ap_login(user, src, ok):
    pid = random.randint(1000, 9999)
    text = (f"Password auth succeeded for '{user}' from {src}:{eport()}" if ok
            else f"Bad password attempt for '{user}' from {src}:{eport()}")
    out.send3164(AP_HOSTNAME, f"dropbear[{pid}]: {text}", AUTHPRIV, SEV_NOTICE if ok else SEV_WARNING)


def eport():
    return random.randint(49152, 65535)


# --- Normal day-to-day traffic -------------------------------------------

def baseline_event():
    kind = random.choices(
        ["lan_web", "lan_dns", "wan_noise", "web_inbound", "vpn_traffic", "guest_web", "dhcp", "icmp", "wifi",
         "switch_port"],
        weights=[30, 20, 20, 10, 8, 6, 3, 3, 4, 1])[0]
    ip, host, mac = random.choice(LAN_CLIENTS)
    if kind == "lan_web":
        filterlog("allow_lan_web", IFACE["lan"], "pass", "in", "tcp", ip, random.choice(BENIGN_IPS),
                  eport(), random.choice([443, 443, 443, 80]))
    elif kind == "lan_dns":
        filterlog("allow_lan_dns", IFACE["lan"], "pass", "in", "udp", ip, LAN_GW, eport(), 53)
        dns_query(ip, random.choice(BENIGN_DOMAINS), random.choice(["A", "A", "AAAA", "HTTPS"]))
    elif kind == "wan_noise":
        filterlog("default_deny", IFACE["wan"], "block", "in", "tcp", random.choice(INTERNET_NOISE_SRC),
                  WAN_IP, eport(), random.choice([22, 23, 445, 3389, 8080, 5900, 1433]))
    elif kind == "web_inbound":
        filterlog("nat_web01_https", IFACE["wan"], "pass", "in", "tcp",
                  f"{random.choice([49, 58, 110, 171, 223])}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
                  SERVERS["web"], eport(), 443)
    elif kind == "vpn_traffic":
        filterlog("allow_vpn_servers", IFACE["vpn"], "pass", "in", "tcp", f"10.8.0.{random.choice([6, 10, 14])}",
                  random.choice([SERVERS["erp"], SERVERS["file"]]), eport(), random.choice([443, 445]))
    elif kind == "guest_web":
        gip = GUEST_CLIENTS[0][0]
        filterlog("allow_guest_web", IFACE["guest"], "pass", "in", "tcp", gip, random.choice(BENIGN_IPS), eport(), 443)
    elif kind == "dhcp":
        dhcp_ack(ip, host, mac, IFACE["lan"])
    elif kind == "wifi":
        if random.random() < 0.3:
            ap_station(WIFI_GUEST, random.choice(["CONNECTED", "DISCONNECTED"]), GUEST_CLIENTS[0][2])
        else:
            ap_station(random.choice(WIFI_STAFF), random.choice(["CONNECTED", "CONNECTED", "DISCONNECTED"]), mac)
    elif kind == "switch_port":
        port = random.choice(SWITCH_PORTS)
        switch_link(port, "down")
        switch_link(port, "up")
    else:
        filterlog("allow_lan_web", IFACE["lan"], "pass", "in", "icmp", ip, "1.1.1.1")


# --- Attack / audit scenarios (each one should trip an alert in Graylog) --

def sc_port_scan():
    for port in random.sample(range(1, 10000), random.randint(25, 40)):
        filterlog("default_deny", IFACE["wan"], "block", "in", "tcp", SCANNER_IP, WAN_IP, eport(), port)


def sc_gui_bruteforce():
    src = GUEST_CLIENTS[1][0]
    for _ in range(random.randint(6, 10)):
        gui_login(random.choice(["root", "admin"]), src, ok=False)


def sc_admin_login_unusual():
    # root logging in from a Sales laptop instead of the management VLAN
    gui_login("root", "192.168.10.23", ok=True)


def sc_config_change():
    gui_login("root", ADMIN_WS, ok=True)
    config_change("root", ADMIN_WS, random.choice(
        ["/api/firewall/filter/apply", "/firewall_rules_edit.php", "/system_usermanager.php"]))


def sc_c2_beacon():
    victim = LAN_CLIENTS[1][0]  # LT-SUDA
    dns_query(victim, C2_DOMAIN)
    sport = eport()
    filterlog("allow_lan_web", IFACE["lan"], "pass", "in", "tcp", victim, C2_IP, sport, 443)
    suricata(2027865, "ET MALWARE Possible Cobalt Strike Beacon Observed", "A Network Trojan was detected",
             1, "TCP", victim, sport, C2_IP, 443)


def sc_phishing_dns():
    dns_query(random.choice(LAN_CLIENTS)[0], PHISH_DOMAIN)


def sc_vpn_bruteforce():
    for _ in range(random.randint(5, 8)):
        vpn_login("admin", BRUTE_IP, ok=False)


def sc_guest_lateral():
    src = GUEST_CLIENTS[1][0]
    for _ in range(random.randint(8, 15)):
        filterlog("block_guest_internal", IFACE["guest"], "block", "in", "tcp", src,
                  random.choice(list(SERVERS.values())), eport(), random.choice([445, 139, 3389, 22, 389]))


def sc_ids_web_attack():
    suricata(2016184, "ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine)",
             "Web Application Attack", 2, "TCP", SCANNER_IP, eport(), SERVERS["web"], 443)
    suricata(2034647, "ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)", "Attempted Administrator Privilege Gain",
             1, "TCP", SCANNER_IP, eport(), SERVERS["web"], 443)


def sc_blocked_category():
    # Unbound blocklist answers 0.0.0.0, so only the DNS queries show up - no connection follows
    ip = LAN_CLIENTS[2][0]  # LT-ANAN
    for _ in range(random.randint(10, 15)):
        dns_blocked(ip, random.choice(BLOCKED_DOMAINS))


def sc_dns_bypass():
    # DoT, plain DNS to an outside resolver and DoH, all stopped by the firewall
    ip, _, _ = random.choice([LAN_CLIENTS[0], GUEST_CLIENTS[1]])
    iface = IFACE["guest"] if ip.startswith("192.168.30.") else IFACE["lan"]
    for _ in range(random.randint(2, 4)):
        filterlog("block_dot", iface, "block", "in", "tcp", ip, random.choice(PUBLIC_RESOLVERS[:2]), eport(), 853)
        filterlog("block_ext_dns", iface, "block", "in", "udp", ip, random.choice(PUBLIC_RESOLVERS), eport(), 53)
        filterlog("block_doh", iface, "block", "in", "tcp", ip, PUBLIC_RESOLVERS[3], eport(), 443)


def sc_vpn_login_ok():
    user = random.choice(VPN_USERS)
    vpn_login(user, f"{random.choice([49, 58, 171])}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}", ok=True)


def sc_unknown_device():
    # a personal laptop joins the Staff Wi-Fi and gets a lease from the unmapped pool; a Pi is plugged into a desk port
    ip, host, mac = ROGUE_LAPTOP
    for _ in range(random.randint(2, 4)):
        ap_station(WIFI_STAFF[0], "POSSIBLE-PSK-MISMATCH", mac)  # guessing the Staff Wi-Fi password first
    ap_station(WIFI_STAFF[0], "CONNECTED", mac)
    dhcp_ack(ip, host, mac, IFACE["lan"])
    switch_port_security(ROGUE_PI_MAC, SWITCH_PORTS[8])


def sc_port_flap():
    port = SWITCH_PORTS[7]
    for _ in range(random.randint(5, 7)):
        switch_link(port, "down")
        switch_link(port, "up")


def sc_netdev_bruteforce():
    # someone on a Sales laptop guesses the switch and AP admin passwords
    src = LAN_CLIENTS[2][0]
    for _ in range(random.randint(5, 8)):
        switch_login(random.choice(["admin", "cisco"]), src, ok=False)
    for _ in range(random.randint(5, 8)):
        ap_login("admin", src, ok=False)


def sc_netdev_login_unusual():
    # switch admin login from the office LAN instead of the management VLAN
    switch_login("admin", LAN_CLIENTS[4][0], ok=True)


def sc_netdev_config_change():
    switch_login("admin", ADMIN_WS, ok=True)
    switch_config("admin", ADMIN_WS)
    ap_login("admin", ADMIN_WS, ok=True)


def sc_integrity_fail():
    # someone edited an archived log file on the Synology share: the monthly verify finds it (OPS-02)
    manifest("verify", failed=True)


def sc_disk_full():
    disk_check(random.randint(76, 88))  # OPS-03


# played with --play only (or --play all): they raise High/Medium SIEM-health alerts
ON_DEMAND = [sc_integrity_fail, sc_disk_full]

SCENARIOS = [sc_port_scan, sc_gui_bruteforce, sc_admin_login_unusual, sc_config_change, sc_c2_beacon,
             sc_phishing_dns, sc_vpn_bruteforce, sc_guest_lateral, sc_ids_web_attack, sc_vpn_login_ok,
             sc_blocked_category, sc_dns_bypass, sc_unknown_device, sc_port_flap, sc_netdev_bruteforce,
             sc_netdev_login_unusual, sc_netdev_config_change]


def play(names):
    """One-shot: play the named scenarios (or 'all') right now, then exit."""
    by_name = {f.__name__.removeprefix("sc_"): f for f in SCENARIOS + ON_DEMAND}
    picked = list(by_name) if names == ["all"] else names
    for name in picked:
        if name not in by_name:
            sys.exit(f"unknown scenario '{name}'. choose from: all, {', '.join(by_name)}")
        by_name[name]()
        print(f"played {name}", flush=True)


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--play":
        play(sys.argv[2:])
        return
    print(f"OPNsense simulator -> {SYSLOG_PROTO}://{SYSLOG_HOST}:{SYSLOG_PORT} "
          f"every {INTERVAL}s (scenario rate {SCENARIO_RATE})", flush=True)
    # announce every known client once so DHCP-based enrichment has data from the start
    for ip, host, mac in LAN_CLIENTS + GUEST_CLIENTS:
        dhcp_ack(ip, host, mac, IFACE["guest"] if ip.startswith("192.168.30.") else IFACE["lan"])
    tick = 0
    while True:
        tick += 1
        n = random.randint(6, 12)
        for _ in range(n):
            baseline_event()
        if tick % 720 == 1:  # hourly at 5 s per tick: the SIEM host's disk check
            disk_check(random.randint(35, 55))
        if tick % 17280 == 1:  # nightly: SHA-256 manifest of new archive files, then a passing verify
            manifest("create")
            manifest("verify")
        played = ""
        if random.random() < SCENARIO_RATE:
            scenario = random.choice(SCENARIOS)
            scenario()
            played = f" + scenario {scenario.__name__}"
        print(f"tick {tick}: {n} baseline events{played}", flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
