# Walkthrough: ซ้อมเกณฑ์ผ่าน POC ข้อ 5–6

| | |
|---|---|
| ประเภทเอกสาร | บทซ้อมทีม (rehearsal script) |
| สถานะ | Draft v0.1 · 2026-10-24 เดินทุกขั้นบน Graylog 7.1.11 ของ POC แล้ว และคำตอบใน drill ตรวจกับข้อมูลจริงในระบบ |
| เกี่ยวข้อง | [REQUIREMENTS.md](REQUIREMENTS.md) หัวข้อ 6 (alert), 7 (ISO mapping), 10 (เกณฑ์ผ่าน POC) · [README](../README.md) |
| ใช้เมื่อ | ซ้อมทีม IT และสาธิตให้ผู้บริหารหรือ auditor ดู ด้วยข้อมูลจำลอง (REQUIREMENTS หัวข้อ 3) |

เกณฑ์ที่บทนี้ใช้ซ้อม (REQUIREMENTS หัวข้อ 10)

- **ข้อ 5:** สำหรับ incident ตัวอย่าง ทีมตอบได้ภายใน 1 นาทีจาก dashboard ว่า ใคร / เครื่องไหน / จาก zone ไหน / ไปที่ไหน / rule ไหน
- **ข้อ 6:** ทีมสาธิต walkthrough แบบที่จะทำให้ auditor ดูได้ (alert → สืบสวน → หลักฐาน)

บทนี้ครอบคลุมเฉพาะสิ่งที่ SIEM ให้ได้ การเปิด ticket และขั้นตอนตอบสนองต่อ incident เป็นกระบวนการของเจ้าของ ISMS

**บทบาท** (คนเดียวทำหลายบทบาทได้ ยกเว้นผู้สืบสวนในข้อ 5 ซึ่งต้องไม่รู้ล่วงหน้าว่าจะเจอ incident ไหน)

| บทบาท | ทำอะไร |
|---|---|
| ผู้ยิง incident | รันคำสั่ง `--play` และจับเวลา |
| ผู้สืบสวน | รับ alert แล้วหาคำตอบจาก dashboard |
| ผู้เล่นเป็น auditor | ถามคำถามในหัวข้อ 4 และขอดูหลักฐาน |

---

## 0. เตรียมก่อนซ้อม (ประมาณ 10 นาที)

1. ตรวจว่า stack พร้อมและ dashboard มีข้อมูลครบ

   ```bash
   docker compose ps                  # ทุก service Up, provisioner Exited (0)
   python3 tools/viz_check.py         # ต้องไม่มี FAIL
   ```

2. เปิด**โหมดเงียบ** คือให้ simulator ส่งแต่ traffic ปกติ ไม่สุ่ม scenario ค่าตั้งต้นสุ่ม scenario ทุก ~20 วินาที จึงมี alert ใหม่แทบทุกนาที ทำให้ incident ที่ซ้อมจมอยู่ในกองนั้น

   ```bash
   SCENARIO_RATE=0 docker compose up -d generator
   ```

3. **รออย่างน้อย 6 นาที** ก่อนยิง drill แรก alert ระดับ High ที่นับเกณฑ์ดูย้อนหลัง 5 นาที จึงยังมี alert ค้างจาก scenario เดิมได้ และ alert ที่เพิ่งส่งอีเมลไปจะไม่ส่งซ้ำในช่วง grace period (ส่วนใหญ่ 5 นาที) WEB-02, NET-04 และ WEB-01 ตรวจเป็นรอบ 5, 10 และ 60 นาที จึงอาจโผล่จาก scenario เดิมอีกหนึ่งครั้งตอนครบรอบ ไม่ต้องสนใจ

4. เปิด tab ไว้ล่วงหน้า

   | Tab | URL |
   |---|---|
   | Mailpit (อีเมล alert) | http://localhost:8025 |
   | Webhook (alert ระดับ High) | http://localhost:8088 |
   | Graylog › Alerts | http://localhost:9000/alerts |
   | Graylog › Dashboards | http://localhost:9000/dashboards |

**ข้อควรรู้ระหว่างซ้อม**

- dashboard แสดง 24 ชั่วโมงล่าสุด และ alert ใหม่อยู่บนสุดของหน้า Alerts
- alert ส่วนใหญ่ขึ้นแถวเดียวต่อ incident ยกเว้น alert ระดับ High ที่นับเกณฑ์ (NET-02, IAM-01, IAM-04, IAM-05) ซึ่งขึ้นได้ถึง 5 แถว เพราะตรวจทุก 1 นาทีโดยดูย้อนหลัง 5 นาทีเพื่อให้แจ้งเร็ว log เดิมจึงถูกนับซ้ำจนพ้นช่วง แต่อีเมลส่งครั้งเดียว (grace period) และ RPT-01 นับเป็นเหตุการณ์เดียว
- จะกรองหน้า Alerts ให้พิมพ์ ID **ในเครื่องหมายคำพูด** ในช่อง Search for events เช่น `"THR-02"` ถ้าไม่ใส่จะได้ alert อื่นปนมาด้วย
- **Show documents for value** จะเพิ่ม widget ชั่วคราวบน dashboard อย่ากด Save ถ้ามีถามตอนออกจากหน้าให้เลือกไม่บันทึก (ถ้าบันทึกไป provisioner จะเขียนทับเมื่อแก้นิยาม dashboard ใน `provision.py`)
- widget รายการ log ค่อนข้างแคบ กดไอคอน fullscreen มุมขวาบนของ widget เพื่อดู field ได้ง่ายขึ้น
- ยิง drill เดิมซ้ำภายใน 5 นาที alert จะขึ้นใน Graylog แต่ไม่มีอีเมลใหม่ (grace period) ให้ใช้ drill อื่นหรือรอ
- IAM-03 (admin login นอกเวลา) เกิดได้เฉพาะ 19:00–07:59 จึงไม่ได้ใช้ในบทนี้

---

## 1. ห้าคำถาม ตอบจาก field ไหน

ทุก log ที่ผ่าน pipeline มี field เหล่านี้ คลิก log บรรทัดใดก็ได้ใน Graylog เพื่อดู

| คำถาม | Field | หมายเหตุ |
|---|---|---|
| ใคร | `src_owner`, `src_department` | login ใช้ `user`, VPN ใช้ `vpn_user` ถ้าว่างแปลว่าเครื่องไม่อยู่ในทะเบียน asset ให้ดู `src_mac` และ `dhcp_hostname` จาก dashboard Identity & admin › DHCP leases |
| เครื่องไหน | `src_host`, `src_ip` | `src_mac` สำหรับ DHCP และ Wi-Fi |
| จาก zone ไหน | `src_zone` | LAN-Office, Server, Guest, Management, VPN, Internet |
| ไปที่ไหน | `dst_ip`, `dst_port`, `dst_host`, `dst_zone` | DNS ใช้ `dns_query` |
| rule ไหน | `fw_rule_desc`, `fw_action` | `fw_rule_id` คือ ID ของ rule ใน OPNsense · IDS ใช้ `ids_signature` · ถ้าเป็น IOC ดู `threat_category` ด้วย |

---

## 2. ข้อ 5: Drill ตอบห้าคำถามใน 1 นาที

**วิธีซ้อม**

1. ผู้ยิงเลือก drill หนึ่งข้อโดยไม่บอกผู้สืบสวน แล้วรัน

   ```bash
   docker compose run --rm --no-deps generator python /app/opnsense_simulator.py --play <scenario>
   ```

2. alert ขึ้นใน Graylog ภายใน ~25 วินาที อีเมลถึง Mailpit ภายใน ~30 วินาที (วัดเมื่อ 2026-10-24)
3. **เริ่มจับเวลาเมื่ออีเมลถึง Mailpit** ผู้สืบสวนอ่านหัวเรื่องอีเมลแล้วไปที่ dashboard
4. **หยุดเวลาเมื่อผู้สืบสวนตอบครบ 5 ข้อ** ผ่านถ้าไม่เกิน 60 วินาทีและตอบถูกทุกข้อ
5. รอบถัดไปใช้ drill อื่น ซ้อมจนทุกคนผ่านครบ 3 drill

### D1 · C2 beacon (มุมมอง: เครื่องภายในติดมัลแวร์)

| | |
|---|---|
| คำสั่ง | `--play c2_beacon` |
| Alert | THR-02 (High), THR-03 (High), THR-01 (High) · Email + Webhook |
| เส้นทาง | Dashboards › **SIEM - Web filtering & threat** › widget **Threat-intel hits by IOC** › คลิก `198.51.100.66` › **Show documents for value** › คลิก log บรรทัดที่ขึ้นต้นด้วย `70,,,5708f9e9…` (filterlog) |

| คำถาม | คำตอบที่ถูก |
|---|---|
| ใคร | `suda.p` แผนก HR |
| เครื่องไหน | `LT-SUDA` (192.168.10.22) |
| zone | LAN-Office |
| ไปที่ไหน | `198.51.100.66:443` (Internet) ซึ่ง threat intel ระบุว่าเป็น c2-server ก่อนหน้านั้นเครื่องนี้ query `cdn-update.malicious-c2.example` |
| rule | **Allow LAN to Internet (HTTP/HTTPS)** ปล่อยผ่าน (`fw_action: pass`) และ IDS จับได้ด้วย signature `ET MALWARE Possible Cobalt Strike Beacon Observed` |

ประเด็น: firewall ปล่อยผ่านเพราะเป็น HTTPS ปกติ ที่รู้ได้เพราะ SIEM เทียบปลายทางกับ threat intel (A.5.7)

### D2 · Guest พยายามเข้าโซนภายใน (มุมมอง: การแยก network)

| | |
|---|---|
| คำสั่ง | `--play guest_lateral` |
| Alert | NET-02 (High) · Email + Webhook |
| เส้นทาง | Dashboards › **SIEM - Firewall & network** › widget **Guest -> internal zones, blocked (ISO A.8.22)** › คลิก `192.168.30.55` › **Show documents for value** › คลิก log บรรทัดใดก็ได้ จากนั้นไป **SIEM - Identity & admin** › widget **DHCP leases** หาแถว `192.168.30.55` |

| คำถาม | คำตอบที่ถูก |
|---|---|
| ใคร | **ไม่อยู่ในทะเบียน asset** (`src_owner` ว่าง) จาก DHCP lease รู้ว่าเครื่องชื่อ `UNKNOWN-PC` MAC `00:0c:29:30:00:55` |
| เครื่องไหน | 192.168.30.55 |
| zone | Guest |
| ไปที่ไหน | Server zone เช่น `SRV-FILE01` (192.168.20.11) port 445, 139, 3389, 22, 389 (simulator สุ่ม server และ port) |
| rule | **Block Guest to internal networks** บล็อก (`fw_action: block`) |

ประเด็น: ตอบ "ใคร" ไม่ได้ก็นับว่าถูก ถ้าบอกได้ว่าเป็นเครื่องนอกทะเบียน พร้อม MAC และชื่อเครื่อง เพราะนั่นคือข้อเท็จจริงที่ต้องรายงาน (A.5.9, A.8.22)

### D3 · Port scan จาก internet (มุมมอง: ภัยจากภายนอก)

| | |
|---|---|
| คำสั่ง | `--play port_scan` |
| Alert | NET-01 (High) · Email + Webhook |
| เส้นทาง | Dashboards › **SIEM - Firewall & network** › widget **Top blocked sources** › คลิก `192.0.2.200` › **Show documents for value** › คลิก log บรรทัดใดก็ได้ |

| คำถาม | คำตอบที่ถูก |
|---|---|
| ใคร | คนภายนอก ไม่ใช่ผู้ใช้ของบริษัท threat intel ระบุว่าเป็น `known-scanner` |
| เครื่องไหน | 192.0.2.200 |
| zone | Internet |
| ไปที่ไหน | WAN ของ firewall `OPNSENSE-WAN` (203.0.113.10, zone WAN-Edge) 25–40 port ภายใน 1 นาที |
| rule | **Default deny / state violation rule** บล็อก (`fw_action: block`) |

ประเด็น: ไม่มีอะไรหลุดเข้ามา แต่ SIEM เห็นและแจ้ง ทำให้ทีมตัดสินใจได้ว่าจะ block IP ถาวรหรือไม่ (A.8.20)

---

## 3. ข้อ 6: Walkthrough ให้ auditor ดู (ประมาณ 15 นาที)

ใช้เรื่องเดียวกับ D1 (C2 beacon บน LT-SUDA) เพราะเห็นครบทุกชั้น: DNS → firewall → IDS → threat intel → ตัวตน ยิง incident สด ๆ ต่อหน้า auditor เพื่อให้เห็นว่าการตรวจจับทำงานจริง ไม่ใช่ภาพที่เตรียมไว้

| # | ทำ | Auditor เห็น | ประเด็นที่พูด | Control |
|---|---|---|---|---|
| 1 | เปิด **SIEM - Overview (management)** | log ทุกแหล่งไหลเข้า (Log volume by category), จำนวน alert, admin login, config change, สุขภาพของ SIEM | log ของ firewall, switch และ AP รวมอยู่ที่เดียว ถูก parse และเติมบริบท สุขภาพของระบบ log เองก็ถูก monitor (OPS-01/02/03) | A.8.15, A.8.16 |
| 2 | รัน `--play c2_beacon` แล้วรอ ~30 วินาที เปิด Mailpit | อีเมล `[SIEM][P3] [THR-02] Allowed traffic to/from threat-intel IOC` มี group by (src_ip, dst_ip, dst_port, threat_category) และ log ดิบที่เป็นต้นเหตุ ในหน้า Webhook มีรายการเดียวกัน | ตรวจพบภายในนาทีเดียวโดยไม่มีคนเฝ้าจอ alert ระดับ High ส่งทั้งอีเมลและ webhook (production ส่งอีเมลอย่างเดียวตาม Q4) | A.8.16, A.5.24–A.5.26 |
| 3 | Graylog › **Alerts** › พิมพ์ `"THR-02"` ในช่อง Search for events › แถวบนสุด › **Details** | เวลา, priority High, group-by fields (src_ip, dst_ip, dst_port, threat_category) | alert ถูกบันทึกเป็นประวัติและค้นย้อนหลังได้ (เก็บ 365 วัน) | A.8.16 |
| 4 | แถวเดียวกัน › **More › Replay search** | แผง Alert/Event Details: นิยาม alert, ตรวจทุก 1 นาทีโดยดูย้อน 1 นาที, ส่งไปที่ Email + Webhook และ log ที่ทำให้เกิด alert | alert มีนิยามชัดเจน ไม่ได้ขึ้นกับดุลยพินิจของคนดู log | A.8.16 |
| 5 | ปิดแผงด้านขวา แล้วคลิก log ใน widget All Messages | field ครบ: `src_owner` suda.p, `src_host` LT-SUDA, `src_zone` LAN-Office, `dst_ip` 198.51.100.66:443, `fw_rule_desc` Allow LAN to Internet, `threat_category` c2-server และ `full_message` (log ดิบที่ OPNsense ส่งมา) | ตอบได้ทันทีว่าใคร เครื่องไหน zone ไหน ไปไหน ผ่าน rule ไหน (ข้อ 5) | A.5.7, A.8.16 |
| 6 | Search: `src_ip:192.168.10.22` ช่วงเวลา 15 นาทีล่าสุด | ลำดับเหตุการณ์ของเครื่องนี้: DNS query ไป `cdn-update.malicious-c2.example` → firewall ปล่อยผ่านไป 198.51.100.66 → IDS จับ Cobalt Strike beacon ปนกับ traffic ปกติ | สืบย้อนได้ว่าเกิดอะไรก่อนหลัง และเครื่องนี้ทำอะไรอีกบ้าง | A.8.15, A.8.16 |
| 7 | **SIEM - Identity & admin** › **DHCP leases** แถว 192.168.10.22 | 192.168.10.22 → `3c:22:fb:10:00:22` → LT-SUDA → suda.p | ชื่อผู้ใช้มาจาก DHCP static mapping ใน OPNsense (sync เป็น `assets.csv` ด้วย `tools/sync_assets.py`) จึงผูก IP กับเจ้าของเครื่องได้ทุกเวลา | A.5.9 |
| 8 | เก็บหลักฐาน (หัวข้อ 3.1) | ไฟล์ CSV, permalink, อีเมล | หลักฐานมาจากระบบโดยตรง ไม่ใช่ข้อความที่พิมพ์ใหม่ | A.5.28 |
| 9 | **SIEM health** บน Overview และเปิด `reports/RPT-01_*.html` | ผลตรวจ SHA-256 ของ archive, disk และรายงานรายเดือนที่มีช่องให้ผู้บริหารลงชื่อทบทวน | log ที่เป็นหลักฐานถูกตรวจว่าไม่ถูกแก้ และมีการทบทวนเป็นรอบ | A.8.15, A.8.16 |

สร้างรายงานสำหรับขั้น 9 ก่อนวันสาธิต

```bash
docker compose run --rm tools /tools/monthly_report.py --last-days 1
```

### 3.1 หลักฐานที่เก็บจาก incident

| หลักฐาน | วิธีเก็บใน Graylog | บอกอะไร |
|---|---|---|
| Alert และรายละเอียด | Alerts › แถว alert › **Details** และแผง Alert/Event Details ใน **Replay search** (capture หน้าจอ) | ตรวจพบเมื่อไร ด้วยเงื่อนไขอะไร แจ้งช่องทางไหน |
| อีเมลแจ้งเตือน | Mailpit (production: mailbox ของทีม) | เวลาที่ทีมได้รับแจ้ง |
| Log ที่เกี่ยวข้อง | Replay search หรือ Search › widget **All Messages** › ไอคอน download › **Export all search results** › เลือก field (`timestamp`, `src_ip`, `src_host`, `src_owner`, `src_zone`, `dst_ip`, `dst_port`, `dst_zone`, `fw_rule_desc`, `threat_category`, `full_message`) › **Start Download** | รายการ log เป็นไฟล์ CSV แนบกับบันทึก incident ได้ |
| Log บรรทัดสำคัญ | คลิก log › **Permalink** | link ที่เปิดกลับมาดู log บรรทัดเดิมได้ตราบที่ยังอยู่ใน retention (90 วัน) |
| Log ดิบ | field `full_message` | ข้อความที่ OPNsense ส่งมาก่อนถูก parse สำเนาที่ Synology มี SHA-256 manifest ยืนยันว่าไม่ถูกแก้ (OPS-02) |

---

## 4. คำถามที่ auditor อาจถาม

| คำถาม | ตอบด้วย | โชว์อย่างไร |
|---|---|---|
| ถ้า log หยุดส่งจะรู้ไหม | OPS-01 แจ้งเมื่อไม่มี log จาก OPNsense 5 นาที | Alerts กรอง `OPS-01` (เกิดทุกครั้งที่เริ่ม stack) หรือทดสอบสดด้วย `docker compose stop generator` รอ ~5 นาที (วัดได้ 5 นาที 7 วินาที เมื่อ 2026-10-24) แล้ว `docker compose start generator` |
| log ถูกแก้ได้ไหม | archive บน Synology แบบ WriteOnce + SHA-256 manifest (NFR-11) ถ้าไฟล์ถูกแก้หรือหายจะเกิด OPS-02 | `--play integrity_fail` แล้วดู alert OPS-02 และ widget SIEM health |
| เก็บ log นานเท่าไร | ค้นได้ 90 วัน, ประวัติ alert 365 วัน (Q2), archive ระยะยาวบน Synology | System › Indices ดู retention ของ index set |
| ใครเข้าถึง SIEM ได้บ้าง | `it-analyst` ค้นและแก้ rule ได้แต่ลบ log ไม่ได้, `log-admin` เป็น break-glass ของผู้บริหาร (Q16) | System › Users and Teams · POC สร้าง user นี้เมื่อใส่ `IT_ANALYST_PASSWORD` และ `LOG_ADMIN_PASSWORD` ใน `.env` แล้วรัน `docker compose run --rm provisioner` ต้องทำก่อนวันสาธิตถ้าจะโชว์ข้อนี้ |
| เวลาใน log เชื่อถือได้ไหม | OPNsense sync NTP แล้วเป็น NTP ให้ทุกอุปกรณ์ (NFR-02) Graylog เก็บเวลาแบบ UTC และแสดงเป็น Asia/Bangkok | message detail แสดง `timestamp` ส่วน `full_message` มีเวลาเดิมจากอุปกรณ์ |
| ทำไม alert บางข้อขึ้นหลายแถว | เฉพาะ alert ระดับ High ที่นับเกณฑ์ เช่น brute force ตรวจทุก 1 นาทีโดยดูย้อนหลัง 5 นาที เพื่อแจ้งภายในนาทีเดียวและไม่พลาด burst log เดิมจึงถูกนับซ้ำจนพ้นช่วง ทีมได้รับแจ้งครั้งเดียวเพราะ grace period และรายงาน RPT-01 นับเป็นเหตุการณ์เดียว alert อื่นตรวจเป็นรอบไม่ทับกันจึงขึ้นแถวเดียว | Alerts › พิมพ์ `"NET-02"` หลัง D2 จะเห็นหลายแถวห่างกัน 1 นาที เทียบกับ Mailpit ที่มีอีเมลฉบับเดียว และ RPT-01 หัวข้อ 2 คอลัมน์ "เหตุการณ์" กับ "แถวใน Graylog" |
| รู้ได้อย่างไรว่า IP นี้เป็นของ suda.p | DHCP static mapping → `assets.csv` → enrich ทุก log | Identity & admin › DHCP leases |
| มีการ review log จริงไหม | dashboard สำหรับดูประจำ และรายงาน RPT-01 รายเดือนที่ผู้บริหารลงชื่อ | `reports/RPT-01_*.html` |
| ข้อมูลที่เห็นเป็นของจริงไหม | **ไม่ใช่** POC ใช้ข้อมูลจำลองที่รูปแบบเหมือน OPNsense จริง pipeline ชุดเดียวกันใช้กับเครื่องจริงได้ การทดสอบกับของจริงอยู่ใน Phase 1 | README หัวข้อ "ขอบเขต POC" |

---

## 5. บันทึกผลการซ้อม

| วันที่ | Drill | ผู้สืบสวน | เวลา (วินาที) | ตอบถูก 5/5 | หมายเหตุ |
|---|---|---|---|---|---|
| | D1 C2 beacon | | | | |
| | D2 Guest lateral | | | | |
| | D3 Port scan | | | | |

Walkthrough (ข้อ 6)

- [ ] ทำครบ 9 ขั้นภายใน 15 นาที
- [ ] alert ของ incident สดถึง Email และ Webhook ภายใน 2 นาที
- [ ] เก็บหลักฐานได้ครบตามหัวข้อ 3.1
- [ ] ตอบคำถามในหัวข้อ 4 ได้โดยไม่ต้องเปิดเอกสาร

---

## 6. หลังซ้อม

คืน simulator เป็นค่าใน `.env` หรือค่าตั้งต้น (สุ่ม scenario ตาม `SCENARIO_RATE`)

```bash
docker compose up -d generator
```
