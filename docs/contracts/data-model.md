# Contract: engine data model

> Agreed in #6 (`agent-A` author, `agent-B` ack). Changing anything here needs a new `type:contract` issue and an `ack` from every owner it affects (WORKFLOW.md §5).

The engine turns one nmap XML file into one `ScanResult`. The CLI, history, UI, content and AI layers all read this shape and nothing else. Until the engine lands, build against the fixtures:

| Fixture | What it shows |
|---|---|
| [`tests/fixtures/contract/example_scan.json`](../../tests/fixtures/contract/example_scan.json) | A readable scan: router, camera, smart hub, TV and an unidentified device. 6 findings, score 35. The camera is the most dangerous device (30 points). The TV (`http` on 8008 with no title) and the router's HTTPS port are deliberately **not** findings. |
| [`tests/fixtures/contract/example_error.json`](../../tests/fixtures/contract/example_error.json) | An unreadable file (`NOT_XML`). |

The fixtures are hand-written, not real scans. Their IDs follow the formulas below with the test salt `test-salt`.

## Python entry point

```python
from tool.engine import analyze_file

result = analyze_file(path)   # never raises on bad input; returns status "error" instead
data = result.to_dict()       # exactly the JSON shape below
```

## `ScanResult`: one per file

| Field | Type | Notes |
|---|---|---|
| `schema_version` | int | `1`. Bumped only through a contract issue. |
| `file` | string | Basename only, never a full path. |
| `status` | `"ok"` \| `"error"` | |
| `error` | object \| null | `{"code": …}` when `status` is `"error"`, otherwise null. Codes below. |
| `scan_start` | string \| null | nmap's `start` attribute as ISO 8601 UTC (`2026-11-07T09:00:00Z`). Null if missing or invalid. |
| `score` | int \| null | Standard score `max(0, 100 − points_total)`. Null when `status` is `"error"`. |
| `points_total` | int | Sum of all finding points. `0` for an error. |
| `devices` | `Device[]` | Sorted by IP, numerically. Empty for an error. |
| `findings` | `Finding[]` | Sorted by IP (numeric), then port (null first), then code. Empty for an error. |

**Error codes:**

| Code | When |
|---|---|
| `EMPTY_FILE` | 0 bytes |
| `TOO_LARGE` | Over the size limit (default 20 MB) |
| `NOT_XML` | Malformed or truncated XML (like V7) |
| `UNSAFE_XML` | An entity declaration or external reference is present (XXE and billion-laughs defence). A bare `<!DOCTYPE nmaprun>` is fine: every real nmap file has one. |
| `NOT_NMAP` | Valid XML, but the root element isn't `nmaprun` |

`scores.csv` shows `ERROR` for all of them. The UI can map each code to a friendlier message.

## `Device`

| Field | Type | Notes |
|---|---|---|
| `device_key` | string | `d_` + the first 12 hex characters of HMAC-SHA256(salt, MAC in upper case), or of the IP when there's no MAC. |
| `ip` | string | Validated by the engine. IPv4; IPv6 only for a host that has no IPv4 address. |
| `mac_masked` | string \| null | Vendor half only: `B8:27:EB:xx:xx:xx`. The raw MAC never leaves the engine. |
| `vendor` | string \| null | **RAW** |
| `hostname` | string \| null | **RAW**. The first hostname nmap reports. |
| `device_type_guess` | enum | `router`, `camera`, `printer`, `pc`, `phone`, `tv`, `iot_hub`, `nas`, `server`, `unknown` |
| `risk_points` | int | Sum of this device's finding points. The highest is "the most dangerous device". |
| `open_ports` | `Port[]` | Only ports in state exactly `open`, sorted by protocol then port. |
| `finding_ids` | string[] | IDs of this device's findings, in finding order. |

## `Port`

| Field | Type | Notes |
|---|---|---|
| `port` | int | |
| `protocol` | `"tcp"` \| `"udp"` | |
| `service_name` | string \| null | **RAW**. nmap's service `name`. |
| `product` | string \| null | **RAW** |
| `version` | string \| null | **RAW** |
| `tunnel` | string \| null | **RAW**. `"ssl"` or null. |
| `http_title` | string \| null | **RAW**. Output of the `http-title` script. |

## `Finding`

| Field | Type | Notes |
|---|---|---|
| `id` | string | `f_` + the first 12 hex characters of SHA-256(`file|ip|port|code`), with an empty string for a null port. Unique within one scan; doesn't depend on the salt. The AI grounding checker cites findings by this ID. |
| `match_key` | string | `m_` + the first 12 hex characters of SHA-256(`device_key|protocol|port|code`), with empty strings for nulls. The **same finding across scans**: history uses it to show resolved findings (V6a → V6b). |
| `code` | string | A catalog code, e.g. `CAMERA_STREAM_EXPOSED`. |
| `severity` | `"high"` \| `"medium"` \| `"low"` \| `"info"` | |
| `points` | int | 20, 10, 5 or 0, from the catalog. |
| `ip` | string | |
| `port` | int \| null | Null for `UNKNOWN_DEVICE`. |
| `protocol` | `"tcp"` \| `"udp"` \| null | Null for `UNKNOWN_DEVICE`. |
| `device_key` | string | The device this finding belongs to. |
| `evidence` | object | `service_name`, `product`, `version`, `tunnel`, `http_title` from the port. All **RAW**, all null for `UNKNOWN_DEVICE`. |

## RAW fields are hostile

The brief says to treat every input as hostile, including the scan files. A field marked **RAW** is a string copied from the scan file:
- The engine caps it at 256 characters and strips control characters. It does nothing else.
- **The UI must escape it** (NFR-03).
- **The AI layer must never send it to the LLM unsanitised** (MASTERPLAN §5.4). For example, send `device_type_guess` instead of `vendor`.

Everything else is produced or validated by the engine: IDs, keys, `code`, `severity`, `points`, `ip`, `port`, `protocol`, `status`, `error.code` and the enums.

## Rules all readers rely on

- **No display text.** The engine outputs codes only. `area:content` owns the RO/EN text, keyed by catalog code, `device_type_guess` and `error.code`.
- **Determinism.** The same file with the same salt gives byte-identical JSON. The CSVs contain neither `id` nor `device_key`, so they're identical on every machine.
- **Ordering scans.** History and the UI order scans by `scan_start`. **When it's null, fall back to the file name**, so both sort the same way.
- **Keys are per install.** `device_key` and `match_key` depend on the local salt, so they're only stable on the same machine. Never compare them across machines. Finding `id` is the same everywhere.
