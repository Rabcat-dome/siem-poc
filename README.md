# SIEM POC: OPNsense → Graylog

POC สำหรับเตรียมตรวจ ISO/IEC 27001:2022 โดยรวม log ของ OPNsense ไว้ที่ Graylog แยก field, เติมบริบทว่า **ใคร / จากไหน / ไปไหน**, และยิง alert ไปยัง Email/Webhook

- Requirement (ภาษาไทย, ใช้คุยร่วมกัน): [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md)
- Diagram (architecture, log journey, alert perspectives, integration points): [docs/architecture.html](docs/architecture.html) เปิดใน browser

```mermaid
flowchart LR
  subgraph SRC[Log sources]
    FW[OPNsense firewall]
    SIM[Log simulator<br/>every 5s]:::poc
    NAS[(Synology NAS<br/>archive)]
  end
  subgraph GL[Graylog SIEM - docker compose]
    IN[Syslog input :1514]
    PIPE[Pipeline<br/>parse · enrich · route]:::focal
    LUT[(Lookup tables<br/>asset · zone · rule · TI · web)]
    OS[(OpenSearch<br/>10 streams)]
    AL[Alert engine<br/>14 event definitions]:::focal
  end
  FW -- syslog --> IN
  FW -- syslog copy --> NAS
  SIM -. simulated .-> IN
  IN --> PIPE --> OS --> AL
  LUT --> PIPE
  AL -- SMTP --> MAIL[Email / Mailpit]
  AL -- HTTP --> HOOK[Webhook<br/>LINE OA · Teams · ticket]
  classDef focal fill:#fbeee9,stroke:#bf4520
  classDef poc stroke-dasharray: 4 3
```

> OPNsense เป็น FreeBSD จึงรันใน Docker ไม่ได้ POC นี้ใช้ **simulator** ส่ง log รูปแบบเดียวกับ OPNsense จริง (RFC5424: filterlog, suricata, audit, openvpn, dhcpd, unbound) ทำให้ pipeline เดียวกันใช้กับเครื่องจริงได้ทันที

## เริ่มใช้งาน

ต้องมี Docker (RAM ว่าง ≥ 4 GB)

```bash
docker compose up -d
```

ครั้งแรกใช้เวลาประมาณ 1–2 นาที `provisioner` จะสร้าง input, lookup table, stream, pipeline และ alert ให้อัตโนมัติ จากนั้น `generator` จะเริ่มยิง log

| URL | ใช้ทำอะไร |
|---|---|
| http://localhost:9000 | Graylog (user `admin` / pass `admin`) |
| http://localhost:8025 | Mailpit: อีเมล alert |
| http://localhost:8088 | Webhook receiver: alert ที่จะส่งไป LINE/Teams/ticketing (refresh ทุก 5 วินาที) |

ดูว่า provisioner ทำอะไรไปบ้าง:

```bash
docker compose logs provisioner
```

## ทดลองใช้

**ดู log ที่ parse แล้ว:** Graylog › Search แล้วลอง query

```text
event_category:firewall AND fw_action:block
src_zone:Guest AND dst_zone:Server
threat_indicator:true
event_type:gui_login_failure
web_policy:block
web_category:social
```

**ดู alert:** Graylog › Alerts (หรือดูที่ Mailpit/Webhook) alert ถูกประเมินทุก 1 นาที ส่วน IAM-03 (admin login นอกเวลา) จะยิงเฉพาะช่วง 19:00–07:59 เวลาไทย

**ยิงทุก scenario ทันที** (ใช้ตอน demo):

```bash
docker compose run --rm --no-deps generator python /app/opnsense_simulator.py --play all
```

หรือเลือกเฉพาะบางตัว เช่น `--play port_scan c2_beacon` (มี `port_scan`, `gui_bruteforce`, `admin_login_unusual`, `config_change`, `c2_beacon`, `phishing_dns`, `vpn_bruteforce`, `guest_lateral`, `ids_web_attack`, `vpn_login_ok`, `blocked_category`, `dns_bypass`)

**ทดสอบ alert "log หาย" (OPS-01):**

```bash
docker compose stop generator
```

รอประมาณ 5–6 นาทีจะมี alert แล้วค่อย `docker compose start generator` (หมายเหตุ: ตอนเริ่ม stack ครั้งแรกจะเห็น OPS-01 หนึ่งครั้ง เพราะยังไม่มี log เข้ามา)

**ปรับความถี่:** `INTERVAL_SECONDS=2 SCENARIO_RATE=0.5 docker compose up -d generator`

## ต่อกับ OPNsense จริง

1. OPNsense › System › Settings › Logging › Remote › Add
   - Transport: UDP(4) หรือ TCP(4) · Hostname: IP ของเครื่องที่รัน POC · Port: `1514`
   - Applications: เลือก filter (filterlog), suricata, audit, openvpn, dhcpd, unbound (หรือเว้นว่างไว้ = ทั้งหมด)
   - **ติ๊ก RFC5424**
2. Firewall rule ที่ต้องการให้เห็น traffic ต้องเปิด "Log packets that are handled by this rule"
3. Intrusion Detection › Administration › เปิด **Enable syslog alerts**
4. Unbound DNS › Advanced › เปิด **Log Queries** (ถ้าต้องการ DNS)
5. แก้ไฟล์ใน `graylog/lookup/` ให้ตรงกับบริษัท (asset จริง, subnet จริง, rule ID จริงซึ่งดูได้จาก Firewall › Log Files › Live View)
   - `fw_rules.csv` คอลัมน์ `tag`: ใส่ `dns-bypass` ให้ rule ที่บล็อก DoT (853), DNS ออกนอก (53) และ DoH resolver เพื่อให้ WEB-02 ทำงาน
   - `web_categories.csv`: ใช้ domain ชุดเดียวกับ blocklist ที่เปิดใน Unbound (policy `block`) และหมวดที่แค่ monitor (policy `monitor`) ใส่ระดับ domain หลัก แล้ว subdomain จะ match ให้เอง
6. เทียบ log จริงกับ regex ใน `graylog/pipeline/*.rule` ถ้ารูปแบบต่างจากที่ simulator ส่ง (เช่นใช้ dnsmasq แทน ISC dhcpd) ให้แก้ rule แล้วรัน provisioner ใหม่

## ยิง traffic จริงผ่าน OPNsense ทดสอบ

แทนที่จะให้ simulator ส่ง log ปลอมเข้า Graylog ตรง ๆ ให้ [traffic-generator](traffic-generator/traffic_generator.py) สร้าง traffic จริงผ่าน **OPNsense ทดสอบ** (ไม่ใช่ตัว production) แล้วให้ OPNsense เขียน log เอง ตัว generator ทำเฉพาะสิ่งที่ผู้ใช้ทั่วไปหรือเครื่องที่ตั้งค่าผิดทำ ได้แก่ เปิดเว็บ, DNS query (รวมถึงโดเมนทดสอบในหมวดที่ถูกบล็อก) และการพยายามใช้ DoT/DoH ส่วน scenario เชิงโจมตี (brute force, scan, C2) ยังใช้ simulator แบบ log เหมือนเดิม

**ตั้งค่า OPNsense ทดสอบ**

1. Remote logging ไปที่เครื่อง SIEM (ดูหัวข้อ "ต่อกับ OPNsense จริง")
2. Unbound DNS › Advanced: เปิด **Log Queries**
3. Unbound DNS › Blocklist: เปิด blocklist และใส่โดเมนทดสอบใน custom list: `thaicasino-bet.example`, `slot-888.example`, `adult-videos.example`, `drugs-shop.example`, `torrent-tracker.example`, `piratebay-mirror.example` (ใช้ destination address ตั้งต้น 0.0.0.0)
4. Firewall › Rules › LAN (วางไว้เหนือ rule allow และเปิด log ทุกข้อ):
   - Block TCP 853 ไป any (DoT)
   - Block TCP/UDP 53 ไปทุกที่ที่ไม่ใช่ LAN address ของ firewall
   - Block TCP 443 ไป alias `doh_resolvers` (`1.1.1.1`, `8.8.8.8`, `8.8.4.4`, `9.9.9.9`)
5. นำ rule ID ของ 3 rule ข้างบน (ดูจาก Firewall › Log Files › Live View) ไปใส่ใน `graylog/lookup/fw_rules.csv` พร้อม tag `dns-bypass`
6. ปิด simulator แบบ log: `docker compose up -d --scale generator=0`

**รันบนเครื่องใน LAN ของ OPNsense ทดสอบ** (Linux + Docker หรือ Python 3 ก็ได้)

```bash
cd traffic-generator && OPNSENSE_DNS=192.168.1.1 docker compose up -d
```

ตรวจว่า control บน OPNsense ทำงานจริงหรือไม่ (ได้ PASS/FAIL ต่อรายการ ใช้เป็นหลักฐาน A.8.23 ได้):

```bash
python3 traffic-generator/traffic_generator.py --dns 192.168.1.1 --play all
```

## Dashboards (FR-11)

provisioner สร้าง 4 dashboard ให้อัตโนมัติ (Graylog › Dashboards) ค่าตั้งต้นแสดง 24 ชั่วโมงล่าสุด

| Dashboard | แสดงอะไร |
|---|---|
| SIEM - Overview (management) | จำนวน alert, admin login, login ล้มเหลว และ config change · ปริมาณ log ตามหมวด · alert ตามระดับ · หมวดเว็บที่ถูกบล็อก |
| SIEM - Firewall & network | block เทียบ pass ตามเวลา · source และ port ที่ถูกบล็อกมากที่สุด · ตาราง zone ต้นทาง × ปลายทาง · Guest พยายามเข้าโซนภายใน (A.8.22) |
| SIEM - Identity & admin | login หน้า GUI สำเร็จ/ล้มเหลว · login ล้มเหลวแยกตาม IP/user · VPN login ล้มเหลว · ตาราง config change ล่าสุด |
| SIEM - Web filtering & threat | หมวดที่บล็อกและหมวดที่ monitor · เครื่องที่เข้าหมวดต้องห้าม · การเลี่ยง DNS filtering · IDS signature · threat intel hits |

ถ้าแก้นิยาม dashboard ใน `provision.py` แล้วรัน provisioner ใหม่ dashboard จะถูกแทนที่ทั้งชุด (รวมถึงการแก้ใน UI) ถ้าไม่ได้แก้นิยาม จะไม่แตะของเดิม

## เครื่องมือ Phase 1

**Retention (Q2):** provisioner ตั้ง log ให้ค้นได้ 90 วัน และประวัติ alert 365 วัน ปรับได้ด้วย `LOG_RETENTION_DAYS` / `EVENT_RETENTION_DAYS` ใน `.env`

**User และสิทธิ์ (Q16):** ใส่ `IT_ANALYST_PASSWORD` และ `LOG_ADMIN_PASSWORD` ใน `.env` แล้วรัน `docker compose run --rm provisioner`
- `it-analyst` สำหรับทีม IT: ค้น log และแก้ pipeline/alert/dashboard ได้ แต่ลบ index, แก้ retention และจัดการ user ไม่ได้ (ทดสอบแล้วได้ 403)
- `log-admin` สำหรับกรณีฉุกเฉิน (break-glass): สิทธิ์ admin เต็ม รหัสให้ผู้บริหารถือไว้

**SHA-256 manifest (NFR-11):** [tools/log_manifest.py](tools/log_manifest.py) ใช้กับ folder archive ของ Synology ตั้งเวลาบนเครื่อง SIEM ที่ mount share ไว้

```text
# crontab: hash ไฟล์ใหม่ทุกคืน และตรวจทั้งหมดทุกวันที่ 1 (ผลส่งเข้า Graylog ถ้าไม่ผ่านจะเกิด OPS-02)
30 1 * * * python3 /opt/siem-poc/tools/log_manifest.py create /mnt/log-archive /mnt/log-manifest --syslog 127.0.0.1:1514
0  2 1 * * python3 /opt/siem-poc/tools/log_manifest.py verify /mnt/log-archive /mnt/log-manifest --syslog 127.0.0.1:1514
```

**รายงานรายเดือน RPT-01:** [tools/monthly_report.py](tools/monthly_report.py) สร้าง HTML ใน `reports/` (มีช่องให้ผู้บริหารลงชื่อทบทวน) และส่งอีเมลได้

```bash
docker compose run --rm tools /tools/monthly_report.py --last-days 1 --email-to management@example.local
```

ไม่ใส่ `--last-days` จะสรุปเดือนก่อนหน้า ตั้ง cron วันที่ 1 ของทุกเดือนได้ ควรตั้ง `REPORT_USER=it-analyst` ใน `.env` เมื่อสร้าง user แล้ว

## ทดสอบ pipeline กับ log ตัวอย่าง

[tests/run_pipeline_tests.py](tests/run_pipeline_tests.py) ส่ง log ตัวอย่างใน [tests/pipeline_cases.json](tests/pipeline_cases.json) ผ่าน pipeline simulator ของ Graylog แล้วเทียบ field ที่ได้ (ตอนนี้มี 37 เคส ครอบคลุมทุก parse rule, การ enrich, filterlog IPv6 และ DHCP แบบ dnsmasq)

```bash
python3 tests/run_pipeline_tests.py            # ทุกเคส (exit 1 ถ้ามีเคสไม่ผ่าน)
python3 tests/run_pipeline_tests.py -v ipv6    # เฉพาะเคสที่ชื่อมีคำว่า ipv6 พร้อมแสดง field ทั้งหมด
```

เมื่อได้ log จริงจาก OPNsense: copy เคสที่ใกล้เคียง ใส่บรรทัด syslog เต็มใน `raw` แล้วใส่ field ที่คาดหวังใน `expect` (`"*"` = ต้องมี field นี้) และ field ที่ต้องไม่มีใน `absent` ถ้าไม่ผ่าน ให้แก้ regex หรือ CSV index ใน `.rule` แล้วโหลด rule ใหม่ด้วย `docker compose run --rm provisioner` ก่อนรันซ้ำ

## Sync ข้อมูลจาก OPNsense

**Asset (Q5):** [tools/sync_assets.py](tools/sync_assets.py) สร้าง `assets.csv` จาก DHCP static mapping ของ OPNsense แล้วรวมกับ `graylog/lookup/assets_static.csv` (server, firewall และเครื่องที่ไม่ได้รับ IP จาก DHCP) ใส่ข้อมูลเจ้าของไว้ใน description ของ static mapping ตามรูปแบบ `owner=somchai.k;dept=Finance;crit=medium`

```bash
OPNSENSE_URL=https://192.168.99.1 OPNSENSE_KEY=... OPNSENSE_SECRET=... python3 tools/sync_assets.py --backend kea --insecure --dry-run
```

ใช้ `--backend kea` หรือ `--backend dnsmasq` ส่วน ISC dhcpd ไม่มี API ให้ export `config.xml` แล้วใช้ `--from-config-xml config.xml` แทน

**หมวดเว็บ (Q13):** [tools/sync_web_categories.py](tools/sync_web_categories.py) สร้าง `web_categories.csv` จาก `graylog/lookup/web_categories_sources.json` (โดเมนที่พิมพ์เอง, ไฟล์ หรือ URL ของ list, มีเพดานจำนวนโดเมนต่อแหล่ง) ใส่ `--opnsense` เพื่อดึง custom blocklist ของ Unbound มารวมด้วย แหล่งแบบ URL ปิดไว้เป็นค่าตั้งต้น

```text
# crontab: asset ทุก 15 นาที, หมวดเว็บทุกคืน (Graylog อ่าน CSV ใหม่เองภายใน 60 วินาที)
*/15 * * * * cd /opt/siem-poc && OPNSENSE_URL=... OPNSENSE_KEY=... OPNSENSE_SECRET=... python3 tools/sync_assets.py --backend kea --insecure
30 2 * * *   cd /opt/siem-poc && python3 tools/sync_web_categories.py
```

endpoint ของ OPNsense ที่ใช้ยืนยันจากเอกสาร API แล้ว แต่ยังไม่ได้ทดสอบกับเครื่องจริง ทดสอบกับ mock เท่านั้น ควรรันด้วย `--dry-run` ก่อนครั้งแรก

## ก่อนขึ้นระบบจริง (hardening)

**Syslog over TLS (NFR-05):** สร้าง CA ส่วนตัวและ cert ของเครื่อง SIEM แล้วรัน provisioner จะได้ input `OPNsense Syslog TLS 6514`

```bash
sh tools/gen_tls_certs.sh siem.example.local 192.168.99.20
docker compose up -d graylog && docker compose run --rm provisioner
```

cert อยู่ใน `tls/` ส่วน key ของ CA อยู่ใน `tls-ca/` (ทั้งสองโฟลเดอร์ไม่ถูก commit) ควรเก็บ key ของ CA ไว้นอกเครื่อง ฝั่ง OPNsense ให้ import `tls/ca.crt` ที่ System › Trust › Authorities แล้วเพิ่ม remote logging แบบ TLS ไปที่ port 6514 โดยใช้ hostname ให้ตรงกับชื่อใน cert

**พอร์ตและการเปิดเข้าถึง:** ตั้งใน `.env` เช่น `SYSLOG_HOST_PORT=514`, `SYSLOG_TLS_HOST_PORT=6514` และ `GRAYLOG_UI_BIND=<IP ใน Management VLAN>:9000` (container ฟังที่ 1514/6514 เหมือนเดิม) อย่า bind UI เป็น `0.0.0.0` และให้ firewall ของเครื่อง SIEM รับ 514/6514 จาก OPNsense เท่านั้น

**ตรวจก่อน go-live:** [tools/preflight_check.py](tools/preflight_check.py) ตรวจ `.env` และ cert แล้วแสดง PASS/WARN/FAIL (exit 1 ถ้ามี FAIL) เช่น รหัสผ่านตั้งต้น, secret ตั้งต้น, รหัสของ user RBAC ว่าง, cert หมดอายุภายใน 30 วัน และการ bind UI

```bash
python3 tools/preflight_check.py --env .env --tls-dir tls
```

## โครงสร้าง repo

```text
docker-compose.yml            # mongodb, opensearch, graylog, provisioner, generator, mailpit, webhook, tools
generator/opnsense_simulator.py  # ยิง log แบบ OPNsense ทุก 5 วินาที + attack scenarios
graylog/pipeline/*.rule       # parse (stage 0) → enrich (stage 1) → route (stage 2)
graylog/pipeline/opnsense.pipeline
graylog/lookup/*.csv          # asset inventory, network zones, firewall rules (+ tag), threat intel, web categories
provisioner/provision.py      # สร้างทุกอย่างผ่าน Graylog REST API (รันซ้ำได้)
webhook/receiver.py           # รับ HTTP notification แทน LINE/Teams/ticketing
traffic-generator/            # traffic จริงผ่าน OPNsense ทดสอบ + ตรวจว่า control บล็อกจริง
tools/log_manifest.py         # SHA-256 manifest ของ log archive (NFR-11)
tools/monthly_report.py       # รายงานรายเดือน RPT-01
tools/sync_assets.py          # DHCP static mapping ของ OPNsense -> assets.csv
tools/sync_web_categories.py  # แหล่ง blocklist -> web_categories.csv
tests/                        # ชุดทดสอบ pipeline rule ผ่าน Graylog simulator
tools/gen_tls_certs.sh        # CA + cert สำหรับ syslog over TLS
tools/preflight_check.py      # ตรวจ .env และ cert ก่อนขึ้นระบบจริง
provisioner/hardening.py      # input syslog TLS 6514
reports/                      # ผลของ RPT-01 (ไม่ commit)
docs/                         # requirement + diagram
```

แก้ rule หรือ alert แล้ว apply ใหม่ (provisioner จะ update rule, pipeline และ alert ที่มีอยู่แล้ว):

```bash
docker compose run --rm provisioner
```

แก้ CSV ใน `graylog/lookup/` ไม่ต้องรันอะไร Graylog อ่านไฟล์ใหม่เองทุก 60 วินาที

## Alert ที่มีใน POC

| ID | Alert | Severity |
|---|---|---|
| NET-01 | Port scan (≥15 distinct ports / 1 นาที / source) | High |
| NET-02 | Guest network พยายามเข้า Server/LAN/Management | High |
| IAM-01 | Brute force หน้า GUI firewall | High |
| IAM-02 | Admin login จากนอก Management zone | Medium |
| IAM-03 | Admin login นอกเวลาทำงาน | Medium |
| IAM-04 | VPN brute force | High |
| CHG-01 | Firewall config ถูกแก้ไข | Low |
| THR-01 | IDS alert priority 1 | High |
| THR-02 | Firewall ปล่อยผ่าน traffic ไป/มาจาก IOC | High |
| THR-03 | DNS query ไป domain อันตราย | High |
| WEB-01 | เครื่องเดิม query หมวดที่ถูกบล็อก ≥ 10 ครั้ง/ชม. | Medium |
| WEB-02 | พยายามเลี่ยง DNS filtering (DoT 853, DNS ภายนอก, DoH) | Medium |
| OPS-01 | OPNsense หยุดส่ง log 5 นาที | High |
| OPS-02 | ตรวจ SHA-256 ของ log archive ไม่ผ่าน (ไฟล์ถูกแก้หรือหาย) | High |

High ส่งทั้ง Email และ Webhook ส่วน Medium/Low ส่ง Email อย่างเดียว รายละเอียดและ ISO mapping อยู่ใน [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md#6-alert-use-cases-ทำงานใน-poc-แล้ว)

## ข้อจำกัดของ POC (ห้ามใช้เป็น production ตามนี้)

- รหัสผ่าน `admin/admin` และ `GRAYLOG_PASSWORD_SECRET` เป็นค่าตั้งต้น ถ้าจะใช้จริงให้ตั้งใน `.env` (ดู `.env.example`) และเก็บรหัส root ไว้เป็น break-glass เหมือน `log-admin`
- OpenSearch ปิด security plugin (ไม่ได้เปิด port ออกนอก docker network) และ UI ยังเป็น HTTP ส่วน syslog เข้ารหัสได้ผ่าน TLS 6514 เมื่อสร้าง cert แล้ว
- Identity (IP → ผู้ใช้) มาจาก CSV ซึ่ง sync จาก DHCP static mapping ได้ แต่ยังไม่ได้ทดสอบกับ OPNsense จริง
- filterlog IPv6 และ DHCP แบบ dnsmasq ทดสอบผ่าน simulator API เท่านั้น ยังไม่เคยเจอ traffic จริง

## ปิด / ล้างข้อมูล

```bash
docker compose down
```

ล้างข้อมูลทั้งหมดเพื่อเริ่มใหม่:

```bash
docker compose down -v
```
