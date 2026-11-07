# Trap files (issue #23)

Our own nmap XML files for the kinds of traps the secret Test Set may use. Every file is hand-written in the shape of `nmap -sS -sU -sV --script http-title -oX` output. None is a real scan. All MACs are made up: a known vendor prefix with `00:00:xx` after it, or a locally administered `02:00:00:00:00:xx` address for "no vendor".

The expected results were worked out by hand from the brief's catalog and detection rules. **No engine has checked them yet.** Wiring them into `make validate` waits for #17.

| Path | What it is |
|---|---|
| `T*.xml` | The trap files. Their answers don't depend on any open question. |
| `expected_findings.csv` | `file,ip,port,finding_code,severity`. The port is empty for `UNKNOWN_DEVICE`. |
| `expected_scores.csv` | `file,network_score`, with `ERROR` for unreadable files. |
| `make_oversized.py` | Writes the oversized trap. That file is never committed. |
| `pending/` | Cases whose answer depends on an open question (#8 or a new one). Their own expected CSVs use our current default. Keep them out of the golden test until each question is answered. |

**Row order:** file, then IP (numeric, IPv4 before IPv6), then port (numeric, empty first), then code. This is the default from #8 question 4 and the contract in #26. If the mentors say order doesn't matter, compare the rows as sets.

## Main traps

The error codes in brackets are the ones the parser in PR #35 gives for each broken file. `scores.csv` only shows `ERROR`.

| File | What it tests | Expected |
|---|---|---|
| `T01_https_admin.xml` | `http` with `tunnel="ssl"` and admin titles ("Router Login", "Admin Settings", "DiskStation - Login") | No findings, 100 |
| `T02_http_admin_titles.xml` | http-title keywords: "WebAdmin", "SETTINGS" on 8080, "Login" on 443 **without** `tunnel="ssl"`, "Device Configuration" on 9000 are findings. Nmap's "Site doesn't have a title", no title at all, "Welcome to nginx!" and "Dashboard" are not | 4 × HTTP_ADMIN_CLEARTEXT, 60 |
| `T03_filtered_ports.xml` | Ports that are `filtered`, `closed` or `open\|filtered` (mysql, telnet, rdp, vnc, snmp, upnp, redis). A host with no vendor and no hostname but no open port isn't UNKNOWN_DEVICE | Only .20:22 SSH_OPEN, 100 |
| `T04_ipv6.xml` | IPv6-only hosts are reported by their IPv6 address. A dual-stack host is reported by its IPv4 address, even though the file lists the IPv6 one first | TELNET, MQTT on .30, CAMERA on `fd00:1:2:3::10`, DB + UNKNOWN on `fd00:1:2:3::99`, 25 |
| `T05_multiple_hostnames.xml` | Three hostnames on one host with no MAC vendor; a host with a hostname but no MAC at all; a host with two hostnames. None is UNKNOWN_DEVICE, and each is counted once | FTP, TELNET (2323), SSH, 70 |
| `T06_method_table_unknown.xml` | `method="table"` services that aren't in the catalog (`sun-answerbook`, `unknown`). An open port is an open port, so .99 is still UNKNOWN_DEVICE. Also has `<hosthint>` elements, which aren't hosts | .99 UNKNOWN_DEVICE, 95 |
| `T07_xxe_external_entity.xml` | XXE: an external entity pointing at `file:///etc/hostname`. Must never be resolved | ERROR (`UNSAFE_XML`) |
| `T08_entity_expansion.xml` | Small billion-laughs (1,000 copies). Our contract (#26) refuses any entity declaration | ERROR (`UNSAFE_XML`) |
| `T09_empty.xml` | 0 bytes | ERROR (`EMPTY_FILE`) |
| `T10_not_nmap.xml` | Well-formed XML whose root isn't `nmaprun` (a made-up inventory format that mentions telnet and rtsp) | ERROR (`NOT_NMAP`) |
| `T11_truncated.xml` | Stops in the middle of a `<port>` element, like V7 | ERROR (`NOT_XML`) |
| `T12_text_output.xml` | nmap's normal text output (`-oN`) saved with an `.xml` name | ERROR (`NOT_XML`) |
| `T13_smb.xml` | SMB_EXPOSED once per device: 139 + 445 gives 445; only 139 gives 139; 139 open with 445 filtered gives 139; `netbios-ns` on UDP 137 isn't SMB | 4 × SMB_EXPOSED, 60 |
| `T14_openssh_versions.xml` | OpenSSH 7.2p2 and 6.6.1p1 (on port 2222) are outdated. 7.4p1, 8.9p1, 10.0p2 (string comparison would get this wrong) and Dropbear are not | 6 × SSH_OPEN + 2 × OUTDATED_SERVICE, 60 |
| `T15_apache_versions.xml` | Apache httpd 2.2.22 and 2.0.52 are outdated, 2.4.7 isn't. All three have admin titles | 3 × HTTP_ADMIN + 2 × OUTDATED, 30 |
| `T16_iis_versions.xml` | IIS 7.5 and 6.0 are outdated, 10.0 isn't (`"10.0" < "7.5"` as strings). All three have admin titles | 3 × HTTP_ADMIN + 2 × OUTDATED, 30 |
| `T17_ftp_samba_versions.xml` | vsftpd 2.3.4 and Samba 3.0.20 each add OUTDATED_SERVICE on the same port. vsftpd 3.0.3 and Samba 4.6.2 don't. Samba 3.0.20 is only open on 445 (the 139 + 445 case is in `pending/`) | 2 × FTP, 2 × SMB, 2 × OUTDATED, 20 |
| `T18_host_down.xml` | A host with `status="down"` is skipped, even though the file lists open telnet and mysql ports for it | Only .71:22 SSH_OPEN, 100 |
| `T19_unknown_device.xml` | UNKNOWN_DEVICE needs no vendor, no hostname and an open port. Only-a-hostname and only-a-vendor hosts don't count. A host with no MAC at all (like the scanning machine itself) does. No open port means not unknown | UNKNOWN on .80 and .83 (empty port), PRINTER, MQTT, TELNET, 55 |
| `T20_upnp_snmp_tcp_udp.xml` | `upnp` and `snmp` count only on UDP and only when `open`. TCP 1900, 5000 and 161 don't count, and neither do `snmptrap`, `smux` or `open\|filtered` UDP. UDP 1900 and TCP 1900 must not give two rows | UPNP on .1:1900, SNMP on .2:161, 80 |
| `T21_clean_network.xml` | Readable scan with no findings: HTTPS, DNS, a TV on 8008/8009, IPP 631 and LPD 515 on a printer, a host with no open ports | No findings, 100 |
| `T22_no_hosts_up.xml` | Valid nmap file with no hosts up | No findings, 100 |
| `T23_score_floor.xml` | 130 points of findings | 7 findings, 0 (never negative) |
| `T24_service_name_lookalikes.xml` | Exact service names only: `tcpwrapped` on 23, `printer`, `ipp`, `ms-sql-s`, `oracle-tns`, `vnc-http`, `secure-mqtt` and `memcache` aren't findings. Catalog names on odd ports are (telnet 2323, postgresql 5433, rtsp 8554, mongodb 27017) | 4 findings on .51, 20 |
| `T25_ip_sort_order.xml` | Hosts out of order in the file. Rows sort numerically (.2 < .9 < .10 < .100, port 1883 < 10883), with UNKNOWN_DEVICE's empty port first. Two `mqtt` ports on one device give two rows | 6 findings, 50 |
| `T26_oversized.xml` | **Not committed.** Run `make_oversized.py`. Just over 21 MiB, above the 20 MiB limit from #10 / #26. Otherwise a valid file with a telnet finding, so an engine that skips the size check reports TELNET_OPEN instead | ERROR (`TOO_LARGE`) |

`T26_oversized.xml` has no row in `expected_scores.csv`, because the file isn't in the folder. When #17 wires the traps in, it should copy the folder to a temp dir, run `make_oversized.py --out <that dir>`, and expect the row `T26_oversized.xml,ERROR`.

### Readings the main set relies on

These aren't open questions in #8, but a reviewer should know about them:
- A finding is reported per port. The same code on two ports of one device gives two rows (T25). SMB_EXPOSED is the only exception the brief makes.
- A host with no MAC address at all has "no MAC vendor" (T05, T19).
- `http` on port 443 without `tunnel="ssl"` is cleartext. The rule looks at the service and the tunnel, not the port (T02).
- An IPv6-only host is reported by its IPv6 address, and a dual-stack host by its IPv4 address (contract #26).
- Internal entities give ERROR because our contract (#26) says so. The brief only names external entities (T08).

## Pending cases (`pending/`)

`pending/expected_*.csv` use the default shown. Move a file into the main set once its question is answered, and update the CSVs if the answer differs from the default.

| File | Question | Default used | Expected with the default |
|---|---|---|---|
| `P01_samba_3x_4x.xml` | #8 Q1: is `Samba smbd 3.X - 4.X` outdated? | No, because the upper bound is 4 | SMB_EXPOSED on 445 only, 90 |
| `P02_method_table_catalog.xml` | #8 Q2: do catalog services that nmap only guessed from the port (`method="table"`) count? Telnet 23, RDP 3389, SNMP UDP 161 | Yes, count them | TELNET, SNMP, RDP, 50 |
| `P03_http_name_variants.xml` | #8 Q3: do `http-proxy` (8080), `http-alt` (8000) and `https` without a tunnel (443) count as `http`? All have admin titles | No, only exactly `http` | No findings, 100 |
| `P04_outdated_without_own_finding.xml` | Not in #8 yet: is OUTDATED_SERVICE reported when the port has no finding of its own? (Apache 2.2.22 with the title "It works!", and Apache 2.2.22 over SSL) | Yes. The catalog says "report when the version is on the outdated list" | 2 × OUTDATED_SERVICE, 60 |
| `P05_outdated_samba_139_and_445.xml` | Not in #8 yet: Samba 3.0.20 on both 139 and 445. One OUTDATED_SERVICE (with SMB on 445) or two? | One, on 445 | SMB + OUTDATED on 445, 70 |
| `P06_http_title_edge_cases.xml` | Not in #8 yet: nmap's "Did not follow redirect to http://…/login.htm" contains "login", and "Log in" (with a space) doesn't. Is the http-title output matched literally? | Yes, a literal case-insensitive substring match | HTTP_ADMIN on .1 only, 90 |

Row order (#8 Q4) affects every expected CSV here; see "Row order" above.
