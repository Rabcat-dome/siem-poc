# Requirement: Centralized Logging & SIEM สำหรับ OPNsense (เตรียมตรวจ ISO/IEC 27001:2022)

| | |
|---|---|
| สถานะ | **Draft v0.6**: ตัดสินใจ Q1–Q16 ครบแล้ว · **POC ใช้ข้อมูลจำลองเท่านั้น** การทดสอบกับอุปกรณ์และ log จริงย้ายไป Phase 1 ([หัวข้อ 3](#3-ขอบเขต)) · ส่วนที่ยังต้องยืนยันอยู่ใน[หัวข้อ 9](#9-คำถามที่ต้องตัดสินใจร่วมกัน) |
| วันที่ | 2026-10-24 |
| POC | `docker compose up -d` ใน repo นี้ (ดู [README](../README.md)) |
| Diagram | [docs/architecture.html](architecture.html) |
| Network architecture | [docs/NETWORK-ARCHITECTURE.md](NETWORK-ARCHITECTURE.md) |
| อ้างอิง | `Document_Summary_ISO27001_WebFiltering_Syslog.xlsx` (tab Web Filtering Guide, Syslog & Log Management) |

---

## 1. ที่มาและปัญหา

**สภาพปัจจุบัน**

- ติดตั้ง OPNsense บน PC ธรรมดา 1 เครื่อง ดู log ได้จากหน้าจอ/Web GUI ของเครื่องนั้นเท่านั้น
- มีการส่ง syslog เข้า **Synology DSM Log Center** แล้ว ช่วยให้ log ไม่หายเมื่อเครื่อง firewall เสีย แต่ log ยังเป็นข้อความดิบ

**ปัญหาที่ต้องแก้**

1. ไม่ได้รวม log ไว้ที่เดียว ดูข้ามอุปกรณ์ไม่ได้
2. ตอบคำถามพื้นฐานของ incident ไม่ได้ว่า **ใคร (who)** ทำ **อะไร (what)** มาจาก **ที่ไหน (from)** ไป **ที่ไหน (to)** และ **เมื่อไร (when)**
3. ไม่มีการแจ้งเตือนเชิงรุก ต้องรอให้คนเข้าไปเปิดดู log เอง
4. ไม่มีหลักฐานว่ามีการ monitor/review log อย่างสม่ำเสมอ ซึ่ง auditor ISO จะขอดู (A.8.15, A.8.16)

### 1.1 OPNsense เป็น NGFW ไหม?

ถ้าใช้แบบ out-of-the-box ยัง**ไม่ใช่ NGFW เต็มรูปแบบ** OPNsense คือ open-source stateful firewall/router บน FreeBSD (ใช้ `pf` และ fork มาจาก pfSense) ความสามารถแบบ NGFW ต้องเปิดเพิ่มดังนี้

| ความสามารถ NGFW | OPNsense ทำได้ด้วย | หมายเหตุ |
|---|---|---|
| Stateful firewall, NAT, VLAN, VPN | built-in | ใช้อยู่แล้ว |
| IDS/IPS | **Suricata** (built-in, Services › Intrusion Detection) | ใช้ rule ET Open ได้ฟรี · แผน: IDS ก่อน แล้วเปิด IPS บาง ruleset (Q8) |
| Application control (L7), user-based policy | plugin **Zenarmor** | ฟีเจอร์หลายตัวต้องซื้อ subscription |
| Web/DNS filtering | Unbound DNS blocklist, Zenarmor | |
| User identity (IP → user) | Captive portal, VPN auth, Zenarmor + AD | **นี่คือช่องว่างหลักของคำถาม "ใครทำ"** |

> ข้อสังเกตด้าน availability: firewall เป็น PC เครื่องเดียว จึงเป็น single point of failure **ตัดสินใจแล้ว (Q12):** ยอมรับความเสี่ยงพร้อม backup config ทุกวัน และให้ผู้บริหารเซ็น risk acceptance (A.8.14)

---

## 2. Gap analysis: Synology Log Center vs SIEM

| ความสามารถ | Synology Log Center | SIEM (Graylog ใน POC) | ISO 27001:2022 |
|---|---|---|---|
| รวม log ไว้ที่เดียว | ✅ | ✅ | A.8.15 |
| แยก field (src/dst/port/action/rule) | ❌ เก็บเป็นข้อความ | ✅ Pipeline rules | A.8.15 |
| ใคร: IP → เครื่อง/เจ้าของ/แผนก | ❌ | ✅ Lookup (asset inventory) | A.5.9, A.8.15 |
| ที่ไหน: IP → network zone, rule ไหน | ❌ | ✅ Lookup (CIDR zones, rule ID) | A.8.22 |
| Threat intelligence matching | ❌ | ✅ Lookup (IOC list, ต่อ feed ได้) | A.5.7 |
| ค้นหา + aggregation (top talker, count, distinct) | พื้นฐาน | ✅ | A.8.16 |
| Alert แบบมีเงื่อนไข/threshold/group by | จำกัด | ✅ Event definitions | A.8.16, A.5.25 |
| แจ้งเตือน Email / Webhook (LINE, Teams, ticket) | Email | ✅ | A.5.26 |
| Dashboard ตามกลุ่มผู้ดู | ❌ | ✅ (ต้องสร้างใน phase 1) | A.8.16 |
| Retention policy / index rotation | ได้ (archive) | ✅ | A.8.15, A.5.33 |
| เก็บระยะยาวแบบแก้ไขไม่ได้ (immutable) | ✅ **Immutable snapshot / WORM** | ⚠️ ต้องทำ archive เพิ่ม | A.8.15, A.5.28 |

**ข้อเสนอ:** ไม่ต้องทิ้ง Synology ใช้ **Graylog เป็น hot storage สำหรับวิเคราะห์และ alert (90 วัน)** และใช้ **Synology เป็นที่เก็บ archive ระยะยาวแบบ immutable** ตามที่ใช้อยู่ ด้วยวิธีนี้ OPNsense ส่ง syslog ไป 2 ปลายทาง (OPNsense ตั้ง remote logging ได้หลาย target)

---

## 3. ขอบเขต

ISMS scope ครอบคลุม**ทั้งบริษัท สำนักงานเดียว** (Q1) จึงใช้ SIEM ชุดเดียวรับ log จากทุกระบบในสำนักงาน โดยติดตั้งบน**เครื่องแยก on-prem ใน Management VLAN** (Q7) ไม่ใช่บน Synology

**ขอบเขตของ POC (ตัดสินใจ 2026-10-24):** POC ใช้**ข้อมูลจำลองเท่านั้น** simulator ส่ง log ของ OPNsense, switch, Wi-Fi AP และผลของ job บนเครื่อง SIEM เป้าหมายคือแสดงว่า log ทุกประเภทถูก parse, เติมบริบท who / what / where, ทำให้เกิด alert และแสดงใน dashboard ได้**ครบถ้วน** ซึ่งตรวจด้วย `tools/viz_check.py` (หัวข้อ 10) **การทดสอบกับอุปกรณ์หรือ log จริงอยู่นอก scope ของ POC** และย้ายไป Phase 1 ทั้งหมด ได้แก่ การเทียบรูปแบบ log จริงของ OPNsense, Unbound blocklist และ switch/AP กับ rule, การยิง traffic ผ่าน OPNsense ทดสอบ และการยืนยันรุ่นอุปกรณ์

| | POC (repo นี้) | Phase 1: Pilot | Phase 2+ |
|---|---|---|---|
| ข้อมูล | **จำลองทั้งหมด** ตรวจความครบด้วย VIZ-CHECK | log จริง เทียบรูปแบบกับ rule | log จริง |
| แหล่ง log | OPNsense, switch, Wi-Fi AP และ job ของเครื่อง SIEM (จำลอง) | OPNsense จริง | **Switch / Wi-Fi AP** จริง (Q9) |
| ขนส่ง | Syslog UDP/TCP | **Syslog over TLS** | Graylog Sidecar / agent |
| Identity | Static CSV (IP, MAC และ VPN tunnel IP → เจ้าของ) | **DHCP static mapping (Q5)** + VPN user, sync mapping → CSV | (ถ้าต้องการ) Captive portal สำหรับ Guest |
| Alert | 20 use cases | ปรับ threshold จากข้อมูลจริง | Correlation หลายแหล่ง |
| แจ้งเตือน | Mailpit + webhook จำลอง | SMTP บริษัท + LINE OA/Teams | Ticketing / SOAR |
| Process | - | Playbook, รอบ review | Monthly report, tabletop exercise |

---

## 4. Functional requirements

ระดับความสำคัญ: **M** = Must, **S** = Should, **C** = Could · สถานะใน POC: ✅ ทำได้แล้ว, ◐ ทำได้บางส่วน, ⬜ ยังไม่ทำ

| ID | Requirement | ระดับ | POC |
|---|---|---|---|
| FR-01 | รับ syslog จาก OPNsense ได้ทั้ง UDP/TCP (และ TLS ใน production) | M | ✅ UDP/TCP 1514 |
| FR-02 | แยก field ของ firewall log (filterlog): action, direction, interface, rule, protocol, src/dst IP, port | M | ✅ IPv4 + IPv6 (IPv6 ทดสอบผ่าน simulator API) |
| FR-03 | แยก field ของ IDS alert (Suricata): signature, classification, priority, src/dst | M | ✅ |
| FR-04 | แยก field ของ admin login (สำเร็จ/ล้มเหลว) และ configuration change พร้อมบอก user และ IP ต้นทาง | M | ✅ |
| FR-05 | แยก field ของ VPN login/session (user → tunnel IP), DHCP lease (IP → MAC → hostname), DNS query และ query ที่ถูก blocklist ตอบ | S | ✅ (DHCP รองรับทั้ง ISC dhcpd และ dnsmasq · log ของ blocklist ใช้รูปแบบจำลอง ดูหัวข้อ 9) |
| FR-06 | **Who**: ระบุ IP เป็นชื่อเครื่อง เจ้าของ แผนก และระดับความสำคัญของ asset โดยอาศัย DHCP static mapping ของเครื่องบริษัท (Q5) | M | ✅ CSV + `tools/sync_assets.py` จาก static mapping (ทดสอบกับ mock) |
| FR-07 | **Where**: ระบุ network zone ต้นทาง/ปลายทาง และชื่อ firewall rule ที่ match | M | ✅ |
| FR-08 | ตรวจ IP/domain กับ threat intelligence | S | ◐ list ภายใน; feed ภายนอก ⬜ |
| FR-09 | Alert rules ตาม use case ในหัวข้อ 6 | M | ✅ 20 rules |
| FR-10 | แจ้งเตือนผ่าน Email (SMTP บริษัท) ทุก severity (Q4) ส่วน Webhook เป็น optional สำหรับ ticketing | M | ✅ แบบจำลอง (Mailpit) |
| FR-11 | Dashboard: ภาพรวมผู้บริหาร, firewall, auth, threat, switch/Wi-Fi | S | ✅ 5 dashboards สร้างโดย provisioner |
| FR-12 | ติดตาม incident ตั้งแต่ alert จนปิดงาน (assign, status, หลักฐาน) | S | ⬜ ใช้ ticketing |
| FR-13 | รายงานรายเดือนสำหรับ management review | S | ✅ RPT-01 `tools/monthly_report.py` ส่ง email วันที่ 1 ด้วย `siem-monthly-report.timer` |
| FR-14 | แจ้งเตือนเมื่อแหล่ง log หยุดส่ง | M | ✅ OPS-01 |
| FR-15 | รับ log จาก Switch และ Wi-Fi AP (Q9) ส่วน NAS/Windows/M365 ยังไม่อยู่ในแผน | S | ◐ จำลองแล้ว (Cisco IOS-style switch, hostapd/dropbear AP) + NET-03/04, IAM-05/06, CHG-02 · รอรุ่นจริงเพื่อแก้ parse rule |
| FR-16 | **Web filtering** แบบ DNS: บล็อกหมวด Security risks และ Illegal บังคับให้ทุกเครื่องใช้ DNS ของ firewall และบล็อก DoH/DoT (หัวข้อ 12.2) | M | ⬜ ตั้งค่าบน OPNsense |
| FR-17 | SIEM ตรวจการเข้าหมวดต้องห้ามและการเลี่ยง DNS filtering (WEB-01, WEB-02) พร้อมรายงานรายเดือนสำหรับ A.8.23 | S | ✅ POC: WEB-01/02 + `tools/monthly_report.py` |

## 5. Non-functional requirements

| ID | Requirement | ค่าที่เสนอ (รอยืนยัน) | ISO |
|---|---|---|---|
| NFR-01 | **Retention** | ✅ ยืนยันแล้ว (Q2): Hot ใน Graylog **90 วัน** (data tiering แบบ hot-only ลบ index เมื่อข้อมูลเก่ากว่า 90–95 วัน) + archive บน Synology **1 ปี** (ดูหมายเหตุกฎหมายด้านล่าง) · POC ✅ provisioner ตั้ง index set แล้ว (events 365 วัน) | A.8.15, A.5.31 |
| NFR-02 | **Time sync** | OPNsense sync จาก `time.nimt.or.th` และ `time.navy.mi.th` แล้วเป็น NTP server ภายในให้ทุกอุปกรณ์ (SIEM host, NAS, switch/AP, PC) เก็บ timestamp แบบ UTC และแสดงผลเป็น Asia/Bangkok | A.8.17 |
| NFR-03 | **Integrity** | Admin ของ firewall ลบหรือแก้ log ใน SIEM ไม่ได้ (แยกหน้าที่) และ archive บน Synology เป็น WriteOnce/immutable ล็อก 1 ปี (Q10) | A.8.15, A.5.3 |
| NFR-04 | **Access control** | RBAC ตาม Q16 (IT ดูและแก้ rule ได้แต่ลบ log ไม่ได้, admin เป็น break-glass ของผู้บริหาร), บัญชีรายบุคคล, MFA สำหรับ SIEM UI และ review สิทธิ์ทุกไตรมาส · POC ✅ user `it-analyst` / `log-admin` (ทดสอบแล้วว่าลบ log ไม่ได้) | A.5.15, A.8.2, A.8.5, A.5.3 |
| NFR-05 | **Confidentiality in transit** | Syslog over TLS และ HTTPS สำหรับ UI · POC ✅ input TLS 6514 + `tools/gen_tls_certs.sh` (ทดสอบ TLS 1.3 แล้ว), UI ยังเป็น HTTP · production ✅ UI เป็น HTTPS (`docker-compose.prod.yml`) | A.8.20, A.8.24 |
| NFR-06 | **Capacity** | ✅ (Q6) < 50 คน ≈ ≤ 50 EPS: 4 vCPU / RAM 8 GB / disk 500 GB รองรับ EPS × 2 · ไม่วัด EPS จริง ใช้ `tools/disk_check.py` ทุกชั่วโมงแทน ถ้า disk ใช้ถึง 75% จะเกิด OPS-03 ให้ขยาย disk ก่อน OpenSearch หยุดเขียนที่ 95% | A.8.6 |
| NFR-07 | **Backup** | Backup config ของ SIEM (MongoDB) และ pipeline/alert ในรูปแบบ code (repo นี้) · ✅ `deploy/backup.sh` ทุกคืน (MongoDB, config เข้ารหัส, config.xml ของ OPNsense) ทดสอบ restore แล้ว | A.8.13 |
| NFR-08 | **PDPA** | log มีข้อมูลส่วนบุคคล (IP, username) จึงต้องระบุวัตถุประสงค์ จำกัดสิทธิ์เข้าถึง และกำหนดระยะเวลาเก็บ | A.5.34 |
| NFR-09 | **Alert latency** | Alert ถึงผู้รับภายใน 2 นาทีหลังเกิดเหตุ | A.8.16 |
| NFR-10 | **Response SLA** | ✅ (Q3) IT in-house รับ alert, High: เริ่มตรวจสอบภายใน 1 ชม. ในเวลาทำการ / ภายใน 2 ชม. แรกของวันทำการถัดไปถ้าเกิดนอกเวลา (นอกเวลาเป็น best effort) | A.5.24, A.5.26 |
| NFR-11 | **Log hashing** | สร้าง manifest SHA-256 ของไฟล์ archive ทุกวัน เก็บไว้ใน folder WriteOnce แยกจากไฟล์ log และสุ่มตรวจ hash ทุกเดือน (บันทึกผลเป็นหลักฐาน) · POC ✅ `tools/log_manifest.py` + alert OPS-02 | A.8.15, A.5.28 |

> **หมายเหตุกฎหมาย:** พ.ร.บ.ว่าด้วยการกระทำความผิดเกี่ยวกับคอมพิวเตอร์ มาตรา 26 กำหนดให้ผู้ให้บริการเก็บข้อมูลจราจรทางคอมพิวเตอร์ไม่น้อยกว่า 90 วัน (เจ้าหน้าที่สั่งขยายได้ไม่เกิน 2 ปี) และประกาศกระทรวงที่เกี่ยวข้องกำหนดให้ต้องระบุตัวผู้ใช้บริการได้ องค์กรที่ให้พนักงานใช้อินเทอร์เน็ตมักถูกนับเป็นผู้ให้บริการ จึงตรงกับโจทย์ "ใครทำ" ข้างต้น **ควรให้ฝ่ายกฎหมายหรือที่ปรึกษายืนยันการตีความกับบริษัท**

**สูตร sizing คร่าว ๆ** (ควรวัด EPS จริงจาก Synology Log Center ก่อน)

```
storage/วัน ≈ EPS × 600 bytes × 86,400 × 1.3 (index overhead)
บริษัทนี้ (< 50 คน) ~50 EPS ≈ 3.4 GB/วัน  → 90 วัน ≈ 300 GB → จัด disk 500 GB
ตัวอย่าง 100 EPS  ≈ 6.7 GB/วัน  → 90 วัน ≈ 600 GB
ตัวอย่าง 300 EPS  ≈ 20  GB/วัน  → 90 วัน ≈ 1.8 TB
RAM: ≤ 50 EPS ใช้ 8 GB รวม (OpenSearch heap 2 GB, Graylog heap 1–2 GB, MongoDB)
     < 500 EPS ใช้ OpenSearch 4–8 GB heap, Graylog 2–4 GB heap
```

ข้อควรระวัง: ถ้าเปิด log ให้ทุก pass rule ปริมาณ log จะสูงมาก ควรเลือก log เฉพาะ rule ที่สำคัญ (block ทั้งหมด, inbound pass, inter-zone, rule ไปยัง server)

---

## 6. Alert use cases (ทำงานใน POC แล้ว)

| ID | มุมมอง | Alert | Logic | Severity | ISO | แจ้งเตือน |
|---|---|---|---|---|---|---|
| NET-01 | Network / Perimeter | Port scan จาก source เดียว | `fw_action:block`, distinct `dst_port` ≥ 15 ใน 1 นาที, group by `src_ip` | High | A.8.20 | Email + Webhook |
| NET-02 | Network segregation | Guest พยายามเข้าโซนภายใน | `src_zone:Guest` → Server/LAN/Mgmt ถูก block ≥ 5 ครั้ง/5 นาที | High | A.8.22 | Email + Webhook |
| IAM-01 | Identity & Access | Brute force หน้า GUI firewall | login fail ≥ 5 ครั้ง/5 นาที ต่อ IP | High | A.8.5 | Email + Webhook |
| IAM-02 | Privileged access | Admin login จากนอก Management zone | login สำเร็จ และ `src_zone ≠ Management` | Medium | A.8.2 | Email |
| IAM-03 | Privileged access | Admin login นอกเวลาทำงาน | login สำเร็จ เวลา 19:00–07:59 | Medium | A.8.2 | Email |
| IAM-04 | Remote access | VPN brute force | VPN login fail ≥ 5 ครั้ง/5 นาที ต่อ user | High | A.8.5, A.6.7 | Email + Webhook |
| CHG-01 | Change | Firewall config ถูกแก้ไข | ทุก config change บอก user, IP และหน้าที่แก้ | Low | A.8.9, A.8.32 | Email |
| THR-01 | Threat / Malware | IDS alert priority 1 | Suricata priority 1 เช่น C2 หรือ exploit | High | A.8.7, A.8.16 | Email + Webhook |
| THR-02 | Threat intel | Traffic ไป/มาจาก IOC และ firewall ปล่อยผ่าน | IP ตรงกับ TI list และ `fw_action:pass` | High | A.5.7 | Email + Webhook |
| THR-03 | Threat intel / DNS | DNS query ไป domain อันตราย | domain ตรงกับ TI list (phishing/C2) | High | A.5.7, A.8.23 | Email + Webhook |
| WEB-01 | Web filtering | เข้าหมวดที่ถูกบล็อกซ้ำ | Unbound ตอบจาก blocklist (`event_type:dns_blocked`: พนัน, ลามก, ยาเสพติด, P2P, malware) ≥ 10 ครั้ง/ชม. ต่อ `src_ip` | Medium | A.8.23 | Email |
| WEB-02 | Web filtering | พยายามเลี่ยง DNS filtering | ถูกบล็อกตอนออก DoT 853, DNS 53 ไปเซิร์ฟเวอร์ภายนอก หรือ DoH resolver ≥ 3 ครั้ง/5 นาที | Medium | A.8.23, A.8.20 | Email |
| OPS-02 | Log integrity | ตรวจ SHA-256 ของ archive ไม่ผ่าน | `log_manifest.py verify` พบไฟล์ถูกแก้หรือหาย | High | A.8.15, A.5.28 | Email + Webhook |
| OPS-01 | Log health | OPNsense หยุดส่ง log | ไม่มี log จาก OPNsense ใน 5 นาที | High | A.8.15, A.8.16 | Email + Webhook |
| OPS-03 | Capacity | disk ของ SIEM ใกล้เต็ม | `disk_check.py` พบ disk ใช้ ≥ 75% (`DISK_WARN_PCT`) แจ้งซ้ำวันละครั้งจนกว่าจะขยาย | Medium | A.8.6, A.8.15 | Email |
| NET-03 | Asset / Network | เครื่องแปลกปลอมในโซน Office | MAC ที่ไม่อยู่ใน `assets_mac.csv` ได้ DHCP lease หรือต่อ Wi-Fi Staff ในโซน LAN-Office หรือ switch บล็อกด้วย port security | Medium | A.5.9, A.8.20 | Email |
| NET-04 | Network | Port ของ switch ขึ้นลงถี่ (flapping) | link down ≥ 5 ครั้ง/10 นาที ต่อ port | Low | A.8.20 | Email |
| IAM-05 | Privileged access | Brute force หน้า admin ของ switch/AP | login fail ≥ 5 ครั้ง/5 นาที ต่อ IP | High | A.8.5 | Email + Webhook |
| IAM-06 | Privileged access | Admin login switch/AP จากนอก Management zone | login สำเร็จ และ `src_zone ≠ Management` | Medium | A.8.2, A.8.5 | Email |
| CHG-02 | Change | Config ของ switch/AP ถูกแก้ไข | ทุก config change บอก user, IP และอุปกรณ์ | Low | A.8.9, A.8.32 | Email |

> คอลัมน์ "แจ้งเตือน" แสดงพฤติกรรมของ POC ส่วนใน production ทุก alert ส่ง **Email อย่างเดียว** ตาม Q4
>
> NET-03/04, IAM-05/06 และ CHG-02 ทำงานกับ log จำลองของ switch/AP (Q9) เมื่อได้รุ่นจริงต้องแก้เฉพาะ parse rule (`graylog/pipeline/6*.rule`) ส่วน alert ไม่ต้องแก้ ตราบที่ rule ใหม่ตั้ง field ชื่อเดิม

**Use case ที่แนะนำให้ทำต่อ (Phase 1–2)**

- Login สำเร็จหลังจาก fail หลายครั้ง (ต้องใช้ correlation ข้ามสอง event)
- Outbound ไป port ที่ไม่ควรออก (SMB/RDP/IRC ออก internet)
- Host ภายในติดต่อปลายทางใหม่ปริมาณมาก (สัญญาณ data exfiltration ต้องใช้ข้อมูล bytes จาก Zenarmor/NetFlow)
- Windows: บัญชีถูก lock, เพิ่มสมาชิกกลุ่ม Domain Admins, ล้าง event log (A.8.2, A.8.15)
- NAS: ลบไฟล์จำนวนมาก (สัญญาณ ransomware)

---

## 7. Mapping กับ ISO/IEC 27001:2022 Annex A (หลักฐานที่ระบบนี้ให้ได้)

| Control | Auditor มักขอดู | หลักฐานจากระบบนี้ |
|---|---|---|
| A.5.7 Threat intelligence | ใช้ข้อมูลภัยคุกคามอย่างไร | Lookup TI + stream "Threat intel hits" |
| A.5.9 Inventory of assets | รายการ asset และเจ้าของ | `assets.csv` / `assets_mac.csv` ที่ใช้ enrich log (ต้องตรงกับทะเบียน asset จริง) + NET-03 จับเครื่องที่ไม่อยู่ในทะเบียน |
| A.5.24–A.5.26 Incident management | ตรวจพบ แจ้ง และตอบสนองอย่างไร | Alert → Email/Webhook → ticket + playbook |
| A.5.28 Collection of evidence | เก็บหลักฐานให้ใช้ได้ทางกฎหมาย | log ที่ไม่ถูกแก้ไข, export จาก Graylog, archive บน Synology |
| A.8.2 Privileged access rights | ติดตามการใช้สิทธิ์ admin | IAM-02, IAM-03, IAM-06, stream `auth`, `Network - switch`, `Network - wifi` |
| A.8.5 Secure authentication | ป้องกัน brute force | IAM-01, IAM-04, IAM-05 |
| A.8.6 Capacity management | วางแผนและเฝ้าดูความจุ | NFR-06 + OPS-03 (`tools/disk_check.py`) |
| A.8.9 / A.8.32 Configuration & change management | ใครแก้อะไรเมื่อไร มี change request ไหม | CHG-01 (firewall), CHG-02 (switch/AP) พร้อม user, IP และ backup file |
| A.8.15 Logging | log ครบ ปลอดภัย และเก็บตาม policy | Centralized, retention, RBAC, OPS-01, WriteOnce archive + SHA-256 manifest (NFR-11) |
| A.8.16 Monitoring activities | มีการ monitor และ review จริง | Alert history, dashboard, บันทึกการ review |
| A.8.17 Clock synchronization | เวลาตรงกันทุกระบบ | NTP config + timestamp ใน log |
| A.8.20 / A.8.22 Network security / segregation | แยก network และตรวจการละเมิด | Zone enrichment + NET-02, NET-03, NET-04 |
| A.8.23 Web filtering | ควบคุมการเข้าเว็บอันตราย | Unbound DNS blocklist + บล็อก DoH/DoT (FR-16), THR-03, WEB-01/02, รายงานรายเดือน (หัวข้อ 12.2) |

> ISO ไม่ได้บังคับว่าต้องใช้เครื่องมือยี่ห้อใด สิ่งที่ auditor ดูคือ **policy + การปฏิบัติจริง + หลักฐาน** เช่น นโยบาย logging, รอบการ review และตัวอย่าง incident ที่ตรวจพบและจัดการแล้ว

---

## 8. ตัวเลือก platform

| ตัวเลือก | จุดเด่น | ข้อจำกัด | เหมาะเมื่อ |
|---|---|---|---|
| **Graylog Open** (POC นี้) | ฟรี, pipeline/lookup/alert ยืดหยุ่น, ไม่หนักมาก | ไม่มี Sigma/correlation/case management/audit log (อยู่ในรุ่นเสียเงิน) | เริ่มจาก network log และต้องการ alert ที่ปรับเองได้ |
| Graylog Security (เสียเงิน) | Sigma rules, anomaly detection, investigation | มีค่า license | ต้องการ SIEM ครบโดยใช้ stack เดิม |
| **Wazuh** | SIEM + XDR ฟรี, agent มี FIM, vulnerability detection, CIS benchmark | ต้องลง agent, ปรับ decoder ของ OPNsense เอง | ต้องการดู endpoint/server ด้วย (ช่วย A.8.8, A.8.9) |
| Security Onion | NSM เต็มรูปแบบ (Zeek, Suricata, PCAP) | กิน resource สูง | มีทีม security ดูแลโดยเฉพาะ |
| Synology Log Center อย่างเดียว | มีอยู่แล้ว | ไม่ใช่ SIEM ตามหัวข้อ 2 | ใช้เป็น archive |

**✅ ตัดสินใจแล้ว (Q11):** ใช้ **Graylog Open** สำหรับ network/firewall และ Synology เป็น archive แบบ open source ล้วน ถ้าอนาคตต้องดู endpoint ให้พิจารณา Wazuh (ฟรีเหมือนกัน และส่งต่อ alert เข้า Graylog ได้)

---

## 9. คำถามที่ต้องตัดสินใจร่วมกัน

**สรุปการตัดสินใจ (2026-10-23, Q1–Q16)**

| # | หัวข้อ | ตัดสินใจ |
|---|---|---|
| Q1 | ISMS scope | ทั้งบริษัท, site เดียว |
| Q2 | Retention | Hot 90 วัน (Graylog) + Archive 1 ปี (Synology) |
| Q3 | ผู้รับ alert / SLA | IT in-house ในเวลาทำการ, นอกเวลา best effort · High เริ่มตรวจภายใน 1 ชม. |
| Q4 | ช่องทางแจ้งเตือน | Email อย่างเดียว |
| Q5 | Identity | DHCP static mapping |
| Q6 | ปริมาณ log | < 50 คน ≈ ≤ 50 EPS · ไม่วัดค่าจริง เฝ้า disk ด้วย OPS-03 แล้วค่อยขยาย |
| Q7 | ที่ติดตั้ง SIEM | เครื่องแยก on-prem ใน Management VLAN |
| Q8 | IDS/IPS | IDS ก่อน แล้วเปิด IPS บาง ruleset |
| Q9 | แหล่ง log Phase 2 | Switch / Wi-Fi AP (ยังไม่ทราบรุ่น จึงจำลองไว้ใน POC) |
| Q10 | Archive | Synology แบบ WriteOnce / immutable |
| Q11 | งบประมาณ | Open source ล้วน + hardware |
| Q12 | Firewall HA | ยอมรับความเสี่ยง + backup config |
| Q13 | Web filtering policy | Block Security + Illegal + P2P, หมวดอื่น monitor |
| Q14 | SSL/TLS inspection | ไม่ทำ ใช้ compensating control |
| Q15 | สำเนา archive นอก site | ยอมรับความเสี่ยง |
| Q16 | Log Administrator | IT ใช้ role จำกัด, ผู้บริหารถือ admin (break-glass) |

**ข้อมูลที่ยังต้องหาเพิ่ม** (อัปเดต 2026-10-23)

> ตาม scope ของ POC (หัวข้อ 3) ข้อที่ยังไม่ติ๊กไม่ใช่เงื่อนไขผ่าน POC ข้อที่ต้องใช้อุปกรณ์หรือ log จริงทำใน Phase 1 ส่วนข้อกฎหมาย, risk acceptance และ antivirus เป็นงานของเจ้าของ ISMS

- [ ] **Synology (Q10):** แจ้งว่าเป็น **DS724+** แต่ไม่พบรุ่นนี้ทั้งในหน้าสินค้าและใน[รายการรุ่นที่รองรับ WriteOnce และ immutable snapshot](https://kb.synology.com/en-global/DSM/tutorial/which_synology_nas_models_support_WriteOnce_and_secure_snapshots) ของ Synology (ตรวจเมื่อ 2026-10-23) รุ่น 2-bay ที่ชื่อใกล้เคียงคือ DS723+, DS224+ และ DS725+ ซึ่งอยู่ในรายการทั้งหมด ให้ดูชื่อรุ่นจริงที่ Control Panel › Info Center และเช็กว่า volume เป็น Btrfs (WriteOnce ต้องใช้ Btrfs)
- [x] **Switch และ Wi-Fi AP (Q9):** ยังไม่ทราบรุ่น **ตัดสินใจ:** จำลองไว้ก่อน simulator ส่ง log ของ switch แบบ Cisco IOS (`%LINK-3-UPDOWN`, `%PORT_SECURITY`, `%SEC_LOGIN`, `%SYS-5-CONFIG_I`) และของ AP แบบ hostapd/dropbear ซึ่ง AP ที่เป็น Linux ส่วนใหญ่ใช้ พร้อม alert NET-03/04, IAM-05/06, CHG-02 เมื่อได้รุ่นจริงให้แก้เฉพาะ parse rule และ `wifi_ssids.csv`
- [ ] **การ์ด network ของ OPNsense (Q8):** น่าจะเป็น Intel ยืนยันก่อนเปิด IPS ที่ Interfaces › Overview ถ้าชื่อ interface เป็น `igb`, `igc`, `em` หรือ `ix` คือ Intel ถ้าเป็น `re` คือ Realtek
- [x] **EPS จริง (Q6):** **ตัดสินใจ:** ไม่วัด ใช้ sizing ตาม Q6 แล้วเฝ้า disk ด้วย OPS-03 (`tools/disk_check.py` ทุกชั่วโมง เตือนที่ 75%) ถ้าเต็มค่อยขยาย
- [ ] ฝ่ายกฎหมายยืนยันการตีความ พ.ร.บ.คอมพิวเตอร์ มาตรา 26 รวมถึงการระบุตัวผู้ใช้ Guest Wi-Fi (Q5)
- [ ] ผู้บริหารเซ็น risk acceptance: firewall ไม่มีเครื่องสำรอง (Q12), Guest ระบุตัวได้แค่ MAC (Q5), NAS/Windows ไม่ได้ส่ง log เข้า SIEM (Q9) และไม่มีสำเนา log นอก site (Q15)
- [x] **Unbound blocklist และ log ของ query ที่ถูก block (หัวข้อ 12.2):** **ตัดสินใจ:** จำลองไว้ก่อน simulator ส่งบรรทัดแบบ `log-local-actions` ของ Unbound เช่น `info: slot-888.example. always_null 192.168.10.23@51234 www.slot-888.example. A IN` แล้ว rule `19b_parse_dns_blocked` ตั้ง `event_type:dns_blocked` ให้ WEB-01, dashboard และ RPT-01 นับ ตอนต่อเครื่องจริงให้เทียบรูปแบบกับ log จริง ถ้าต่างให้แก้ rule 19b ถ้าเครื่องจริงไม่ log query ที่ถูก block ให้เปลี่ยน `DNS_BLOCKED` ใน `provision.py` และ `monthly_report.py` เป็น `web_policy:block` (lookup หมวดจาก `web_categories.csv` แทน)
- [ ] ยืนยันว่าทุกเครื่องมี antivirus (เช่น Microsoft Defender) เปิดอยู่และอัปเดต เพราะเป็น compensating control หลักของ Q14
- [x] **การต่อ ISP:** ADSL, public IP ไม่ fixed แต่ทำ DDNS ได้ ดูผลกระทบใน [NETWORK-ARCHITECTURE หัวข้อ 7](NETWORK-ARCHITECTURE.md#7-การต่อกับ-isp-decision-record)

**รายละเอียดแต่ละข้อ**

- [x] **Q1 ISMS scope:** ISO ครอบคลุม site และระบบใดบ้าง firewall และ log อยู่ใน scope ทั้งหมดหรือไม่
  - **ตัดสินใจ:** ทั้งบริษัท, site เดียว
  - **ผลกระทบ:** ทุกระบบ IT ในสำนักงานอยู่ใน scope ใช้ SIEM ชุดเดียว (collector ตัวเดียว) แต่ Phase 2 ต้องรับ log ให้ครบทุกระบบที่ถือข้อมูลสำคัญ ไม่ใช่แค่ firewall (ดู Q9)
- [x] **Q2 Retention:** hot กี่วัน archive กี่ปี (ขั้นต่ำตามกฎหมาย 90 วัน)
  - **ตัดสินใจ:** Hot ใน Graylog 90 วัน + Archive บน Synology 1 ปี
  - **ผลกระทบ:** NFR-01 ยืนยันตามค่านี้ Phase 1 ต้องสร้าง index set ที่ rotate รายวันและเก็บ 90 index และต้องคำนวณ disk จาก EPS จริง (Q6)
- [x] **Q3 ผู้รับผิดชอบ alert:** IT in-house กี่คน / MSSP / นอกเวลาทำงานใครรับ และ SLA การตอบสนองเท่าไร
  - **ตัดสินใจ:** IT in-house ดูแลในเวลาทำการ ส่วนนอกเวลาเป็น best effort (alert High ส่งเข้ามือถือ แต่ไม่มีเวร on-call)
  - **SLA (alert High):** เริ่มตรวจสอบภายใน 1 ชั่วโมงในเวลาทำการ ถ้าเกิดนอกเวลาให้เริ่มภายใน 2 ชั่วโมงแรกของวันทำการถัดไป
  - **ผลกระทบ:** เพิ่ม NFR-10 และต้องเขียน incident procedure ให้ตรงกับที่ทำจริง เพื่อไม่ให้เป็น nonconformity ตอน audit
- [x] **Q4 ช่องทางแจ้งเตือน:** Email / LINE OA (LINE Notify ปิดบริการแล้ว ต้องใช้ Messaging API) / MS Teams / Telegram
  - **ตัดสินใจ:** Email อย่างเดียว ผ่าน SMTP ของบริษัท
  - **ผลกระทบ:** การรับ alert High นอกเวลาตาม Q3 จะพึ่งการแจ้งเตือนอีเมลบนมือถือ ทีม IT ต้องเปิด notification ของอีเมลบริษัทบนมือถือ (อาจตั้ง rule ให้อีเมลที่ subject ขึ้นต้นด้วย `[SIEM][P3]` เด้งเป็น VIP) ส่วน Webhook ใน POC เก็บไว้สาธิต และใช้ต่อ ticketing ได้ภายหลัง
- [x] **Q5 Identity source:** มี AD/LDAP ไหม, ทำ DHCP static mapping ให้เครื่องบริษัทได้ไหม, Wi-Fi guest ใช้ captive portal หรือไม่
  - **ตัดสินใจ:** ใช้ DHCP static mapping กับเครื่องบริษัททุกเครื่อง (ไม่มี AD และไม่ทำ captive portal ในเฟสนี้)
  - **ผลกระทบ:**
    - `assets.csv` จะแม่นยำตราบที่ static mapping กับ CSV ตรงกัน จึงต้องมี process รับเครื่องใหม่ (เพิ่ม mapping + อัปเดต CSV) ผูกกับ change management
    - Phase 1 ควรมี script export static mapping จาก OPNsense API มาเป็น CSV อัตโนมัติ เพื่อไม่ต้องดูแลสองที่
    - **VPN:** ตั้ง Client Specific Overrides ของ OpenVPN ให้ทุก user ได้ tunnel IP คงที่ แล้วใส่ IP นั้นใน `assets_static.csv` traffic ที่มาทาง VPN จึงบอกได้ว่าเป็นของใคร (POC ใช้ 10.8.0.6 / .10 / .14)
    - **ความเสี่ยงที่ยอมรับ:** (1) ระบุได้ระดับเจ้าของเครื่อง ไม่ใช่คนที่นั่งหน้าเครื่องจริง ถ้ามีเครื่องใช้ร่วมกันต้องจดไว้ในทะเบียน (2) ผู้ใช้ Guest Wi-Fi ระบุตัวได้แค่ MAC/hostname ควรบันทึกเป็น risk acceptance และทบทวนกับฝ่ายกฎหมายเรื่องหน้าที่ระบุตัวผู้ใช้บริการ
- [x] **Q6 ปริมาณ log:** EPS จริงจาก OPNsense (ดูจาก Synology) เพื่อทำ sizing
  - **ตัดสินใจ:** บริษัทมีพนักงานน้อยกว่า 50 คน จึงประเมินไว้ที่ ≤ 50 EPS
  - **ผลกระทบ:** sizing เป้าหมายคือ 4 vCPU / RAM 8 GB / disk 500 GB สำหรับ hot 90 วัน (~300 GB บวก headroom)
  - **อัปเดต (2026-10-23):** ไม่วัด EPS จริง ถ้าพื้นที่เต็มค่อยขยาย จึงเพิ่ม OPS-03 เตือนเมื่อ disk ใช้ถึง 75% เพราะถ้าปล่อยถึง 95% OpenSearch จะหยุดเขียนและ log ใหม่จะหาย (ขัดกับ A.8.15) ควรเลือกเครื่องที่เพิ่ม disk ได้ หรือใช้ LVM เพื่อขยาย volume ได้โดยไม่ต้องย้ายข้อมูล
- [x] **Q7 ที่ติดตั้ง SIEM:** VM บน Synology (VMM), server แยก หรือ cloud
  - **ตัดสินใจ:** เครื่องแยก on-prem (mini PC หรือ server เล็ก RAM 16 GB, SSD 1 TB) รัน docker compose ชุดเดียวกับ POC
  - **ผลกระทบ:**
    - log มี 2 สำเนาอยู่คนละเครื่อง (SIEM = hot, Synology = archive)
    - วางเครื่องใน Management VLAN และให้ firewall เปิดเฉพาะ syslog จาก OPNsense → SIEM ส่วน UI `:9000` เข้าได้จาก Management zone เท่านั้น
    - ต่อ UPS และ backup config (MongoDB + repo นี้) ไปที่ Synology ทุกวัน
    - เข้ารหัส disk ถ้าทำได้ เพราะ log มีข้อมูลส่วนบุคคล
- [x] **Q8 IDS หรือ IPS:** ต้องการแค่ตรวจจับหรือให้ block อัตโนมัติด้วย
  - **ตัดสินใจ:** เริ่มด้วย IDS 2–4 สัปดาห์เพื่อ tune false positive จากข้อมูลใน SIEM แล้วจึงเปิด IPS (drop) เฉพาะ ruleset ที่แม่นสูง (malware/C2, abuse.ch)
  - **ผลกระทบ:**
    - ก่อนเปิด IPS ต้องเช็กว่าเครื่อง OPNsense ใช้การ์ด Intel (รองรับ netmap) และ CPU รับไหว · **อัปเดต:** น่าจะเป็น Intel ยืนยันจากชื่อ interface (หัวข้อ "ข้อมูลที่ยังต้องหาเพิ่ม")
    - การเปิด IPS เป็น change ที่ต้องผ่าน change management (CHG-01 จะจับได้)
    - เพิ่ม use case ใน Phase 1: "IPS dropped" สำหรับรายงาน และ "IDS alert เดิมซ้ำจากเครื่องเดิม" เพื่อหาเครื่องที่ติดเชื้อ
- [x] **Q9 แหล่ง log Phase 2:** AD, file server, ERP, M365, switch/AP
  - **ตัดสินใจ:** Phase 2 เพิ่ม log จาก Switch และ Wi-Fi AP
  - **ผลกระทบ:**
    - ส่ง syslog เข้า input `:1514` เดิมได้ แต่ต้องเขียน pipeline rule ตามยี่ห้อ · **อัปเดต:** ยังไม่ทราบรุ่น POC จึงจำลอง log แบบ Cisco IOS (switch) และ hostapd/dropbear (AP) ไว้ก่อน ได้ stream `Network - switch`, `Network - wifi`, dashboard "SIEM - Switch & Wi-Fi" และ alert NET-03/04, IAM-05/06, CHG-02
    - use case ที่ได้: เครื่องแปลกปลอมเสียบ port / MAC ใหม่ที่ไม่อยู่ใน DHCP static mapping (ต่อยอดจาก Q5), port flapping, login หน้า admin ของ switch/AP
    - **ช่องว่างที่ต้องรับทราบ:** NAS, Windows และ cloud email ไม่ได้ส่งเข้า SIEM จึงต้องใช้ log ในตัวของแต่ละระบบเป็นหลักฐาน A.8.15 พร้อมเขียนรอบการ review ให้ชัด (เช่น เปิด Log Center ของ Synology ดูทุกเดือน) ควรทบทวนเรื่อง NAS ในรอบถัดไป เพราะต่อเข้า SIEM ได้ง่ายและเป็นที่เก็บข้อมูลสำคัญ
- [x] **Q10 Synology:** เก็บเป็น archive ต่อ และเปิด immutable snapshot ได้หรือไม่
  - **ตัดสินใจ:** เก็บ archive บน Synology แบบแก้ไขไม่ได้ ด้วย shared folder แบบ WriteOnce (WORM) หรือ immutable snapshot ตามที่รุ่นและ DSM รองรับ
  - **ผลกระทบ:**
    - ต้องเช็กรุ่น NAS, DSM version และ volume ว่าเป็น Btrfs หรือไม่ · **อัปเดต:** แจ้งว่าเป็น DS724+ แต่ไม่มีรุ่นนี้ในรายการของ Synology ต้องยืนยันชื่อรุ่น (รุ่นใกล้เคียง DS723+, DS224+, DS725+ รองรับ WriteOnce ทั้งหมด)
    - ตั้ง archive ของ Log Center ให้ลง folder ที่ล็อกไว้ 1 ปี (ตาม Q2) และจำกัดสิทธิ์ folder ไม่ให้ admin firewall เข้าถึง
    - ใช้เป็นหลักฐาน A.8.15 และ A.5.28 (log ไม่ถูกแก้ไข)
- [x] **Q11 งบประมาณ:** ยอมจ่าย license (Zenarmor, Graylog Security) หรือใช้ open source ล้วน
  - **ตัดสินใจ:** Open source ล้วน (Graylog Open, Suricata ET Open, OPNsense community) จ่ายเฉพาะ hardware ตาม Q7
  - **ผลกระทบ:**
    - ไม่มี Sigma rules, correlation หรือ audit log ของ SIEM (ฟีเจอร์ของรุ่นเสียเงิน) alert จึงเป็น event definition ที่ทีมดูแลเองใน repo นี้
    - OPNsense ยังไม่เป็น NGFW เต็มรูปแบบ (ไม่มี application control แบบ Zenarmor) ส่วน web filtering ใช้ blocklist ของ Unbound แทน
    - การตรวจสอบว่าใครเข้า SIEM ต้องใช้ access log ของ Graylog และ OS แทน audit log
- [x] **Q12 Firewall HA:** ต้องการเครื่องสำรองหรือ CARP หรือไม่
  - **ตัดสินใจ:** ยอมรับความเสี่ยง ไม่มีเครื่องสำรอง แต่ backup config ของ OPNsense
  - **ผลกระทบ:**
    - ต้องทำ **risk acceptance** เป็นลายลักษณ์อักษร ระบุ downtime ที่คาดไว้ (รอซื้อและติดตั้งเครื่องใหม่) และให้ผู้บริหารเซ็นรับทราบ เพื่อใช้เป็นหลักฐาน A.8.14 / A.5.30
    - ตั้ง backup config ของ OPNsense อัตโนมัติไป Synology ทุกวัน และทดลอง restore ลงเครื่องทดสอบอย่างน้อยปีละครั้ง
    - ระหว่างที่ firewall ล่ม SIEM จะยิง OPS-01 ซึ่งช่วยยืนยันระยะเวลา downtime ได้

**คำถามเพิ่มเติมจากเอกสารข้อกำหนด ISO (หัวข้อ 12)**

- [x] **Q13 นโยบาย web filtering หมวด Productivity / Bandwidth** (social media, เกม, streaming, cloud storage) ตอนนี้ทำได้ฟรีแค่ block ทั้งวันหรือปล่อยแล้ว monitor ส่วน warn page และการคุมตาม application ต้องใช้ Zenarmor ซึ่งขัดกับ Q11
  - **ตัดสินใจ:** Block หมวด Security risks, Illegal และ **P2P/torrent** ส่วนหมวดอื่น (social, streaming, cloud storage, เกม) ปล่อยใช้ได้ แต่ log ไว้และรายงานทุกเดือน
  - **ผลกระทบ:**
    - P2P บล็อก 2 ชั้น คือ DNS blocklist หมวด torrent (ทำได้ทันที) และ Suricata rule กลุ่ม P2P เมื่อเปิด IPS (Q8)
    - ต้องเขียน Acceptable Use Policy ให้ตรงกัน: ระบุหมวดที่ห้าม และแจ้งว่าบริษัทบันทึกการใช้งานอินเทอร์เน็ต (PDPA)
    - รายงานรายเดือน (RPT-01) ต้องมีหมวดที่ใช้ bandwidth สูง เพื่อให้ผู้บริหารทบทวนว่าจะคุมเพิ่มหรือไม่
- [x] **Q14 SSL/TLS inspection:** ข้อเสนอคือ*ไม่ทำ* เพราะต้องลง CA ทุกเครื่อง กิน CPU บน PC ธรรมดา และเห็นข้อมูลส่วนตัว (PDPA) ต้องเขียนเหตุผลไว้ใน risk treatment plan
  - **ตัดสินใจ:** ไม่ทำ SSL/TLS inspection และใช้ compensating control แทน
  - **เหตุผล (ใส่ใน risk treatment plan):** PC ที่ใช้เป็น firewall รับภาระถอดรหัสไม่ไหว, ต้องลง CA ทุกเครื่องและหลายแอปใช้ไม่ได้เพราะ certificate pinning, จะเห็นข้อมูลส่วนตัวของพนักงาน (PDPA) และทีม IT 1–2 คนดูแลไม่ไหว
  - **Compensating controls:**
    - Antivirus/EDR บนทุกเครื่อง (เช่น Microsoft Defender) สแกนไฟล์หลัง browser ถอดรหัสแล้ว (A.8.7)
    - DNS filtering + reputation alias บล็อกปลายทางอันตรายตั้งแต่ก่อนเชื่อมต่อ (FR-16)
    - Suricata ตรวจ TLS SNI/JA3 fingerprint และ IOC ได้โดยไม่ต้องถอดรหัส (Q8)
    - SIEM จับ traffic ไปยัง IOC (THR-01/02/03)
- [x] **Q15 สำเนา archive นอก site:** เอกสารแนะนำให้ backup ไป "ภายนอกที่ปลอดภัยสูง" แต่ตอนนี้ archive อยู่บน Synology ใน site เดียว ถ้าไฟไหม้หรือโดน ransomware ทั้ง site ก็หายทั้งหมด (ทางเลือก: external disk เข้ารหัสหมุนเก็บนอก site, Hyper Backup ไป cloud หรือยอมรับความเสี่ยง)
  - **ตัดสินใจ:** ยอมรับความเสี่ยง ไม่มีสำเนานอก site (SIEM และ Synology อยู่ในออฟฟิศเดียวกัน)
  - **ผลกระทบ:**
    - เพิ่มในเอกสาร risk acceptance ฉบับเดียวกับ Q12 ระบุว่าถ้าเกิดภัยกับทั้ง site (ไฟไหม้, น้ำท่วม, ransomware ทั้ง network) log ทั้งหมดอาจหาย และไม่ตรงกับคำแนะนำ "backup ภายนอก" ในเอกสารข้อกำหนด
    - ลดความเสี่ยงบางส่วนได้ด้วยสิ่งที่ตัดสินใจไปแล้ว: WriteOnce บน Synology (Q10) ช่วยกัน ransomware ลบหรือแก้ archive และ SIEM อยู่คนละเครื่อง (Q7)
    - ควรทบทวนข้อนี้ทุกปีใน management review
- [x] **Q16 Log Administrator:** ใครเป็นผู้ดูแล log ที่แยกจาก admin firewall (ทีม IT มี 1–2 คน ถ้าแยกคนไม่ได้ ต้องใช้ WriteOnce + SHA-256 + การ review ของผู้บริหารเป็น compensating control)
  - **ตัดสินใจ:** IT ใช้ role จำกัด ส่วนผู้บริหารหรือ ISMS manager ถือรหัส admin ไว้ใช้เมื่อจำเป็น (break-glass)
  - **รายละเอียด:**
    - **IT:** ใน Graylog ได้สิทธิ์ดู log, แก้ pipeline rule, alert และ dashboard แต่ไม่มีสิทธิ์ลบ index, แก้ retention หรือจัดการ user · ใน Synology เข้า folder archive ได้แบบอ่านอย่างเดียว
    - **ผู้บริหาร / ISMS manager:** ถือรหัส admin ของ Graylog และ Synology เก็บใน password manager หรือซองปิดผนึก ทุกครั้งที่ใช้ต้องบันทึกเหตุผลและวันที่
    - **Compensating controls:** WriteOnce (Q10), SHA-256 manifest (NFR-11) และ review รายงาน RPT-01 + OPS-01 ทุกเดือน
  - **ผลกระทบ:** Phase 1 ต้องสร้าง role ใน Graylog ตามนี้ และย้ายรหัส admin ที่ตั้งไว้ใน POC (`admin/admin`) ไปให้ผู้ถือ

---

## 10. เกณฑ์ผ่าน POC

ทุกข้อวัดกับ**ข้อมูลจำลอง** (หัวข้อ 3)

1. simulator ส่ง log ครบทุกประเภท (OPNsense, switch, Wi-Fi AP และ job ของเครื่อง SIEM) และแสดงใน Graylog ภายใน 10 วินาที
2. pipeline test ผ่านทุกเคส (`tests/run_pipeline_tests.py`) และไม่มี `gl2_processing_error`
3. **ความครบถ้วนของการ visualize:** `tools/viz_check.py` ไม่มี FAIL คือทุก widget ใน dashboard มีข้อมูล, ทุก `event_type` ที่ simulator ส่งมีอย่างน้อย 1 widget ที่แสดงรายละเอียด (ไม่ใช่แค่กราฟปริมาณตามเวลา) และ field who / what / where ของแต่ละ `event_type` มีค่า ≥ 95%
4. Alert ทั้ง 20 ข้อเกิดได้จาก scenario ของ simulator (`--play all` ส่วน OPS-01 ทดสอบโดยหยุด simulator) และแจ้งเตือนถึง Email/Webhook ภายใน 2 นาที
5. สำหรับ incident ตัวอย่าง ทีมตอบได้ภายใน 1 นาทีจาก dashboard ว่า ใคร / เครื่องไหน / จาก zone ไหน / ไปที่ไหน / rule ไหน
6. ทีมสาธิต walkthrough แบบที่จะทำให้ auditor ดูได้ (alert → สืบสวน → หลักฐาน)

## 11. Roadmap

| Phase | ระยะเวลา (ประมาณ) | งาน |
|---|---|---|
| 0 POC | 1–2 สัปดาห์ | repo นี้ด้วย**ข้อมูลจำลองทั้งหมด**: simulator, pipeline test, alert 20 ข้อ, dashboard 5 ชุด และ VIZ-CHECK ผ่านตามหัวข้อ 10 (ไม่ทดสอบกับของจริง) |
| 1 Pilot | 2–4 สัปดาห์ | **เริ่มทดสอบกับของจริง:** OPNsense ทดสอบบนเครื่อง x86 + `traffic-generator`, ต่อ OPNsense จริงแล้วเทียบรูปแบบ log (รวม Unbound blocklist) กับ rule, ยืนยันรุ่น NAS และการ์ด network · ซื้อและติดตั้งเครื่อง SIEM ใน Management VLAN (Q7), index set 90 วัน (Q2), Synology WriteOnce (Q10), SMTP บริษัท (Q4), DHCP static mapping + sync asset CSV ด้วย `tools/sync_assets.py` กับ OPNsense จริง (Q5), IDS mode (Q8), backup config OPNsense (Q12), DNS web filtering + บล็อก DoH/DoT (FR-16), SHA-256 manifest (NFR-11), NTP ตาม NFR-02, TLS, RBAC/MFA ตาม Q16 และ dashboard |
| 2 Expand | 1–2 เดือน | Switch / Wi-Fi AP จริง (Q9): แก้ parse rule จำลองให้ตรงรุ่นจริง, TI feed ภายนอก |
| 3 Operate | ต่อเนื่อง | review alert รายสัปดาห์, report รายเดือน, tabletop exercise, tune rule |

---

## 12. ตรวจเทียบกับเอกสารสรุปข้อกำหนด ISO (Web Filtering / Syslog)

ที่มา: `Document_Summary_ISO27001_WebFiltering_Syslog.xlsx` (tab "Syslog & Log Management" และ "Web Filtering Guide")

สถานะ: ✅ ครบหรืออยู่ในแผนแล้ว · ◐ ทำได้บางส่วน · ⬜ ยังไม่มี ต้องเพิ่ม · ➖ ไม่ทำ (ต้องมีเหตุผลรองรับใน risk treatment)

### 12.1 Syslog & Log Management (A.8.15, A.8.17, พ.ร.บ.คอมพิวเตอร์ มาตรา 26)

| องค์ประกอบ | เอกสารกำหนด | สถานะ | ของเราทำอย่างไร / ต้องเพิ่มอะไร |
|---|---|---|---|
| Log sources | NGFW, switch, router, server, web proxy, security appliance ส่ง syslog UDP/TCP 514 และตั้ง log level ให้เหมาะสม | ◐ | OPNsense ✅, switch/AP จำลองใน POC แล้ว ของจริงอยู่ใน Phase 2 (Q9), server/NAS ไม่ส่ง (เป็นช่องว่างใน Q9), ไม่มี web proxy · **port:** POC ใช้ 1514 เพราะ Graylog ไม่ได้รันเป็น root ใน production ให้ map host `514` → container `1514` ได้ · **log level:** log เฉพาะ rule ที่สำคัญ (หัวข้อ 5) |
| Collector | Graylog, ELK, rsyslog ฯลฯ ส่งผ่าน syslog over TLS (6514) **หรือ** แยก Management VLAN | ✅ | Graylog (Q11) บนเครื่องแยกใน Management VLAN (Q7) ผ่านเงื่อนไขนี้แล้ว ส่วน TLS 6514 อยู่ใน NFR-05 เป็นงานเสริม |
| Retention | Hot ≥ 90 วัน + archive 1–2 ปี · sizing 2–5 MB/user/วัน | ✅ | Q2: 90 วัน + 1 ปี · ตรวจกับสูตรในเอกสาร: 50 คน × 5 MB = 250 MB/วัน ≈ 23 GB/90 วัน ต่ำกว่าค่าที่ประเมินจาก EPS (~300 GB) มาก disk 500 GB จึงเหลือเฟือ ค่าจริงจาก Q6 จะเป็นตัวตัดสิน |
| Time sync | ทุกอุปกรณ์ sync กับ NTP เดียวกัน เช่น `time.navy.mi.th`, `time.nimt.or.th` | ✅ | ปรับ NFR-02 ให้ระบุ server แล้ว (OPNsense เป็น NTP ภายใน) |
| Integrity | read-only, **SHA-256 hashing**, แยกสิทธิ์ Log Administrator, auto-archive + backup ภายนอก | ◐ | read-only/immutable ✅ (Q10) · SHA-256 ✅ `tools/log_manifest.py` (NFR-11) · แยก Log Admin ✅ IT ใช้ role จำกัด + ผู้บริหารถือ admin (Q16) · backup นอก site ➖ ยอมรับความเสี่ยง (Q15) |

### 12.2 Web Filtering (A.8.23, A.8.20)

เนื่องจากใช้ open source ล้วน (Q11) จึงไม่มี Zenarmor หรือ Secure Web Gateway ตารางนี้ระบุสิ่งที่ OPNsense ทำได้ฟรี

> **Web filtering ต่างจาก IPS อย่างไร:** ทั้งสองอย่าง block ได้เหมือนกัน แต่ web filtering ตอบว่า *"พนักงานไปเว็บนี้ได้ไหม"* (policy, A.8.23) ส่วน IPS ตอบว่า *"traffic นี้เป็นการโจมตีไหม"* (threat, A.8.20/A.8.7) และ SSL/TLS inspection ไม่ใช่วิธี block แต่เป็นตัวถอดรหัส HTTPS ให้ตัวกรองอื่นมองเห็นข้างใน ถ้าไม่ทำ SSL inspection ทุกชั้นจะเห็นแค่ IP, โดเมน และ metadata จึงใช้ DNS filtering + IP/Reputation + IPS ช่วยกันคนละชั้น

**เทคนิคการบล็อก**

| เทคนิค | สถานะ | ทำได้ด้วยอะไร |
|---|---|---|
| DNS-based filtering (sinkhole, บล็อก DoH/DoT) | ⬜ ทำได้ทันที | Unbound DNS › Blocklist (เลือก list malware, phishing, gambling, adult ฯลฯ) + NAT redirect port 53 ของทุกเครื่องมาที่ Unbound + บล็อก outbound 853 (DoT) + บล็อก DoH resolver ด้วย alias list |
| URL/Domain categorization | ◐ | ได้ระดับ domain ผ่าน blocklist แยกตามหมวด ส่วน category database แบบ real-time ต้องใช้ Zenarmor |
| IP/Port filtering | ✅ | Firewall rule + alias (URL table) |
| SSL/TLS inspection | ➖ (Q14) | **ไม่ทำ** ใช้ compensating control แทน: antivirus บนเครื่อง, DNS filtering, reputation และ Suricata ตรวจ TLS SNI/JA3 |
| Application & content filtering | ◐ | Suricata rule กลุ่ม P2P/policy ใน IPS mode บล็อก torrent และ proxy บางส่วนได้ (หลังเปิด IPS ตาม Q8) ส่วน App-ID เต็มรูปแบบต้องใช้ Zenarmor |
| Geo-IP / reputation | ⬜ ทำได้ทันที | GeoIP alias (ใช้ MaxMind license ฟรี) สำหรับ inbound + reputation alias (Spamhaus DROP, abuse.ch) |

**หมวดเว็บมาตรฐาน**

| กลุ่ม | นโยบายในเอกสาร | ทำได้แค่ไหน | SIEM ตรวจอย่างไร |
|---|---|---|---|
| Security risks (malware, phishing, C2, cryptomining) | Block เสมอ | ✅ DNS blocklist + Suricata + reputation alias | THR-01/02/03 ✅ |
| Illegal & unethical (พนัน, ลามก, ยาเสพติด, อาวุธ, ความรุนแรง) | Block เสมอ | ◐ DNS blocklist ครอบคลุมพนัน/ลามก/ยาเสพติด ส่วนอาวุธ/ความรุนแรงยังไม่มี list ฟรีที่ครอบคลุมดี | WEB-01 ✅ POC |
| Bandwidth abusers (P2P, streaming, cloud storage) | Block / quota / limit | ✅ (Q13) **P2P: block** ด้วย blocklist + Suricata P2P · streaming/cloud storage: **monitor** | Dashboard top talkers + RPT-01 |
| Productivity loss (social, เกม, หางาน, หาคู่) | Warn / time-based | ➖ (Q13) **monitor อย่างเดียว** ตาม Acceptable Use Policy เพราะไม่มี warn page และ time-based block ไม่แม่นกับเว็บที่ใช้ CDN | รายงาน DNS ตามหมวด (RPT-01) |
| Business & general | Allow + monitor & log | ✅ DNS query log → stream `OPNsense - dns` (FR-05) | ✅ |
| Unrated / NRDs (โดเมนจดใหม่) | Block / warn / review | ◐ ใส่ NRD blocklist สาธารณะเป็น custom blocklist ของ Unbound | Review รายสัปดาห์ |

**Use case ใหม่สำหรับ SIEM (FR-17)**: WEB-01 และ WEB-02 ทำงานใน POC แล้ว (WEB-01 นับ query ที่ Unbound ตอบจาก blocklist และได้หมวดจาก `web_categories.csv`, การเลี่ยง DNS มาจาก tag `dns-bypass` ใน `fw_rules.csv`) ส่วน RPT-01 ทำแล้วด้วย `tools/monthly_report.py` (FR-13)

| ID | Alert | Logic (ร่าง) | ISO |
|---|---|---|---|
| WEB-01 | เครื่องเดิมพยายามเข้าหมวดต้องห้ามซ้ำ | Unbound ตอบจาก blocklist ≥ 10 ครั้ง/ชม. ต่อ `src_ip` (หมวดมาจาก `web_categories.csv` ชุดเดียวกับ blocklist) | A.8.23 |
| WEB-02 | พยายามเลี่ยง DNS filtering | traffic ออก port 853, ไป DoH resolver ที่บล็อกไว้ หรือ DNS 53 ไปเซิร์ฟเวอร์ภายนอกโดยตรง | A.8.23, A.8.20 |
| RPT-01 | รายงานรายเดือน | top หมวดที่ถูกบล็อก / top เครื่อง / แนวโน้ม ใช้เป็นหลักฐาน A.8.23 และนำเข้า management review (Clause 9.3) | A.8.23, Cl. 9 |
