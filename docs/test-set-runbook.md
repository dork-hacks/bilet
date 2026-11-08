# Test Set morning: the runbook

The secret Test Set is released at **08:00 EET on Sunday (06:00 UTC, hour 20)**, through a shared link and on a USB stick. It holds about 9 nmap XML files with new traps, a before/after pair and an unreadable file (brief, "Secret Test Set").

| Hour | Time (EET) | What has to be true |
|---|---|---|
| 20 | 08:00 | Test Set released. From now on, only fixes for crashes or wrong results, each with an issue (WORKFLOW.md §9). |
| 21 | 09:00 | **The submission form closes for everyone.** `findings.csv`, `scores.csv` and a UI screenshot are uploaded. **Code freeze. Tag `final` on the uploaded commit right away.** |
| 22 | 10:00 | Hard deadline for the `final` tag. |

Test Set accuracy is 30% of the score:
- Every expected row earns credit.
- Every extra row costs the same.
- A correct score per file adds a bonus.
- **If the jury's live re-run of a file differs from the upload, the 30% becomes 0.**

So the upload, the `final` tag and the laptop used for the jury must all be the same build.

**Who:** two people on the **scanner laptop**. One runs the commands. The other reads along and ticks each pass line. Someone also posts in issue #1.

**Where:** the repo checkout on the scanner laptop (here `~/bilet`). Every command below runs from that folder. `tool` and `bilet` are the same command (#101).

Two folders **outside the repo**, so no `git clean` or `make clean` can touch them:

```bash
TS=~/testset            # the Test Set files, as received
UP=~/bilet-upload       # what we uploaded, plus the evidence for it
```

Every step below was dry-run on 7 Nov with the Validation Set standing in for the Test Set ([Dry run](#dry-run-7-nov) at the end).

---

## Before 08:00 (start at 07:30)

### 1. Right laptop, right commit

```bash
cd ~/bilet
git switch main && git pull --ff-only
git status --porcelain          # pass: prints nothing at all
git log --oneline -1            # write this commit in #1
```

**Pass:**
- You're on the scanner laptop: the one the jury will see, and the one with nmap for the live checks.
- You're on `main` at the same commit as `origin/main`.
- `git status --porcelain` prints nothing, so there are no local edits or stray files.

### 1b. The deliverables are in this commit

The `final` tag is everything the jury gets (brief, "Deliverables and submission checklist"), and nothing merges after step 3. So check now that this commit has every deliverable that lives in the repo:

```bash
ls tests/fixtures/lab/                                    # the lab captures (#34)
grep -ohE 'addr="([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"' tests/fixtures/lab/*.xml \
  | grep -vE ':00:00:0[0-3]"'                             # pass: prints nothing
grep -n "stand-in" docs/live-checks.md                    # pass: prints nothing
wc -w docs/technical-summary.md                           # pass: under about 700 words
grep -n "^## " README.md                                  # pass: Setup, Analyse scan files, Live scan
```

**Pass:**
- `tests/fixtures/lab/` holds at least two `.xml` captures that form a before/after pair, plus `expected_findings.csv`. The brief asks for "your own hotspot lab scans (nmap XML) including one before/after pair".
- Every MAC in them is the form that `lab/sanitize` writes (`…:00:00:01` camera, `…:02` server, `…:03` hub, `…:00` other), so no real MAC is in the repo (NFR-02).
- `docs/live-checks.md` check 6 runs on our own captures, not the Validation Set's V6a → V6b stand-in.
- `docs/technical-summary.md` fits on one page. Its "Lab setup" matches the lab on the table: the number of Pis, their roles and the default score. It also covers architecture, assumptions, limitations and LLM use.
- The README explains setup, the live scan and file analysis.

If one of them fails, **stop** and post in #1 what's missing. Its owner (#146) merges the fix before step 3. Then start again at step 1.

### 2. Setup and the checks, all green

```bash
make setup                      # pinned dependencies into .venv (NFR-10)
make validate
make test
make lint
.venv/bin/python --version      # pass: Python 3.12.x
mkdir -p "$UP" && .venv/bin/pip freeze > "$UP/pip-freeze.txt"
```

**Pass:**

```
ok   tests/fixtures/validation
ok   tests/fixtures/traps (+ generated T26_oversized.xml)
1015 passed, 1 skipped            (the count grows as tests are added; 0 failed is what matters)
All checks passed!
```

A single `FAIL` or `failed` means **stop**. Don't take that commit to the Test Set: fix it first, through an issue and a PR, then start again at step 1.

### 3. Freeze merges

```bash
gh issue edit 1 -R dork-hacks/bilet --add-label agents:paused
gh issue comment 1 -R dork-hacks/bilet --body "[human:<name>] Merge freeze from now until the Test Set upload. Upload build: <commit from step 1>."
```

`agents:paused` stops every agent loop (WORKFLOW.md §10), so no agent merges anything into `main` while we work.

**Pass:** the label is on #1 and the comment names the commit.

---

## At 08:00

### 4. Copy the Test Set to its own folder

From the USB stick or shared download, unpack the archive first. Point `SOURCE` at
that unpacked folder. Use a **new, empty** `$TS`; keep every supplied file, including
an extensionless broken file and any notes. Do not rename inputs.

```bash
SOURCE="/path/to/unpacked Test Set"
SOURCE="$SOURCE" TS="$TS" UP="$UP" .venv/bin/python - <<'PY'
import hashlib
import json
import os
import shutil
from pathlib import Path

source = Path(os.environ["SOURCE"]).resolve()
target = Path(os.environ["TS"]).resolve()
if not source.is_dir() or target == source or target.is_relative_to(source):
    raise SystemExit("Choose a source folder and a separate, empty Test Set folder")
if target.exists() and any(target.iterdir()):
    raise SystemExit("TS is not empty: choose a fresh folder; do not mix Test Sets")
if any(path.is_symlink() for path in source.rglob("*")):
    raise SystemExit("Source contains a symbolic link: ask the organizers for regular files")
shutil.copytree(source, target, dirs_exist_ok=True)
manifest = {}
for path in sorted(target.rglob("*")):
    if path.is_file():
        with path.open("rb") as stream:
            manifest[path.relative_to(target).as_posix()] = hashlib.file_digest(stream, "sha256").hexdigest()
upload = Path(os.environ["UP"])
upload.mkdir(parents=True, exist_ok=True)
(upload / "testset-sha256.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
print(f"Copied and hashed {len(manifest)} supplied files")
PY
ANALYZE_ARGS=()    # keep this array for every analysis; step 7 may set --all-files
```

**Pass:**
- The supplied file count matches the organizers' package, including notes if present.
- `$UP/testset-sha256.json` records **all** copied files, not only `*.xml`; JSON safely
  preserves filenames containing spaces, punctuation or newlines.
- Scan inputs are at the top level, as expected by `analyze`. Ask the organizers if
  the package uses subfolders; do not silently drop or overwrite duplicate names.
- The default analyzer reads visible `.xml` files in any letter case. Step 7 names
  other candidate files; `--all-files` includes visible regular files except CSVs
  and Markdown notes. Those exclusions stay copied and checksummed.

### 5. Analyse twice and compare (NFR-05)

```bash
.venv/bin/tool analyze "$TS" --out out/testset --lang en "${ANALYZE_ARGS[@]}"
.venv/bin/tool analyze "$TS" --out out/testset-run2 --lang en "${ANALYZE_ARGS[@]}"
cmp out/testset/findings.csv out/testset-run2/findings.csv &&
  cmp out/testset/scores.csv out/testset-run2/scores.csv && echo DETERMINISTIC
```

**Pass:**
- Each run ends with `N files, M findings, K unreadable -> out/testset/findings.csv, out/testset/scores.csv`, where N is the number of selected scan inputs (not the copied notes or answer keys).
- `DETERMINISTIC` is printed.
- `scores.csv` has one CSV record per selected file, plus its header; step 11 checks the exact filename set using a CSV reader.

Each unreadable file prints one line before the summary, like `V7_broken.xml: This file is damaged or incomplete, so it can't be read. (NOT_XML)`. A Python traceback instead of the summary is a crash: see [What can go wrong](#what-can-go-wrong).

### 6. Review every `ERROR` row

```bash
grep ',ERROR' out/testset/scores.csv
```

The brief promises **one** unreadable file. For each `ERROR` row, the near-miss report (step 7) shows the reason, for example `ERROR (NOT_XML: ParseError: unclosed token: line 23, column 87)`. Confirm it by hand:

```bash
F=<file>.xml
ls -l "$TS/$F"                  # 0 bytes? over 20 MiB?
head -c 400 "$TS/$F"; echo      # starts like an nmap file? <!ENTITY ... ?
tail -c 300 "$TS/$F"; echo      # does it stop in the middle of a tag?
```

| Code | Really unreadable when |
|---|---|
| `EMPTY_FILE` | The file is 0 bytes. |
| `NOT_XML` | It stops mid-tag (truncated), or it isn't XML at all (nmap's text output, a CSV…). |
| `NOT_NMAP` | It's well-formed XML, but the root isn't `<nmaprun>`. |
| `UNSAFE_XML` | It declares an `<!ENTITY` (XXE or entity expansion). We never resolve those, by design (#26). |
| `TOO_LARGE` | It's over 20 MiB (the parser's limit). |

**Pass:** every `ERROR` file really is one of these.

If a file looks like a normal, complete nmap file and we still say `ERROR`, that's an engine bug. Go to [What can go wrong](#what-can-go-wrong).

### 7. Near-miss report: settle each line against the brief's catalog

```bash
make near-misses DIR="$TS" | tee "$UP/near-misses.txt"
```

The report changes nothing. For each file it lists the places where the engine's answer rests on a reading of the brief, in a table with five columns:
- `IP` and `PORT`;
- `CHECK`;
- `ENGINE`: what `tool analyze` reported there;
- `DETAIL`.

It ends with the files it skipped, a total and a legend of the checks it printed.

Settle each line with this table. **"Keep" is the right answer unless the brief plainly says otherwise.** Every reading below is the brief's catalog or a decision recorded in #8, and the golden test checks it with a trap file.

| CHECK | What the engine does | Why (and the trap that checks it) | Change it only if |
|---|---|---|---|
| `name-lookalike` | Nothing: `http-proxy`, `http-alt`, `https`, `vnc-http`, `secure-mqtt`, `microsoft-ds?` aren't catalog names. | The catalog matches nmap's exact service name. #8: only exactly `http` counts (T24, T29). | The brief names that exact service in the catalog. |
| `ssl-tunnel` | `http` over SSL: no HTTP_ADMIN_CLEARTEXT. Any other catalog service over SSL still counts. | HTTP_ADMIN_CLEARTEXT is about cleartext (T01, V1, V5). | Never for http. For ftp and telnet, only if the brief says SSL makes them safe. |
| `catalog-port` | Nothing: the port is usual for a catalog service, but nmap names another (`tcpwrapped` on 23). | The catalog is decided by service name, not port number (T24). | Never. |
| `udp-only` | Nothing: `upnp` and `snmp` on TCP. | The catalog says UDP for both (T20). | Never. |
| `table-guess` | **Counts** a catalog name nmap only guessed from the port number (`method="table"`). | Settled on #8 (T28). | Never. |
| `version-unsure` | A version range is judged by its upper bound: `3.X - 4.X` isn't outdated. A missing or unreadable version is never outdated. | Settled on #8 (T27). The catalog's outdated list is exact. | The version clearly is on the list, and the engine misread its format. That's a bug. |
| `unknown-1-port` | **Counts** UNKNOWN_DEVICE: no vendor, no hostname, at least one open port. | The catalog's rule. One port is enough (T06, T19, V4). | Never. |
| `vendor-text` | The vendor is a placeholder such as "Unknown". It still counts as a vendor, so no UNKNOWN_DEVICE. | A literal reading of "no MAC vendor". **Not settled on #8.** | The answer looks wrong for this file. Ask a mentor before changing anything. |
| `open-filtered` | Nothing. | Only `open` counts (T03, T20). | Never. |
| `no-ipv4` | An IPv6-only host is reported by its IPv6 address. A host with no valid address is skipped. | Contract #26 (T04). | Never. |
| `title-near` | Nothing: "Log in", "Dashboard" or a typo isn't a catalog keyword. | #8: titles match as a literal, case-insensitive substring (T02, T32). | Never. |
| `title-inside-word` | **Counts:** "WebAdmin" contains "admin". | The same literal substring match (T02). | Never. |
| `redirect-title` | Nothing: "Did not follow redirect to …/login" isn't a title. | Settled on #8, item 7 (T32). | Never. |

**Pass:** every line is settled as "keep", and the file ends `… 0 skipped`, unless a skipped file is clearly not part of the Test Set.

**A skipped file that belongs to the Test Set** (no `.xml` ending, for example the unreadable one): `tool analyze` also names it on stderr. Don't rename it, because the file name is a CSV column. Re-run steps 5 and 6 with `--all-files`, which reads every visible file except CSVs and `*.md`, so it gets its `ERROR` row (#203):

```bash
ANALYZE_ARGS=(--all-files)
.venv/bin/tool analyze "$TS" --out out/testset --lang en "${ANALYZE_ARGS[@]}"
.venv/bin/tool analyze "$TS" --out out/testset-run2 --lang en "${ANALYZE_ARGS[@]}"
cmp out/testset/findings.csv out/testset-run2/findings.csv &&
  cmp out/testset/scores.csv out/testset-run2/scores.csv && echo DETERMINISTIC
```

Keep `ANALYZE_ARGS` in this shell for steps 8 and 11, so every run reads the same files. If you open another terminal, set the same array there first.

If a line really contradicts the brief:
1. Open an issue (`type:bug`, `area:engine`, `prio:p0`) with the line and the brief's sentence.
2. Fix it in a PR that keeps `make validate` green, and merge it.
3. Start again at step 1 on the new commit.

**After 08:40, don't start a fix.** Upload what the engine gives: a correct upload with one doubtful row beats a missed deadline.

### 8. UI screenshot

```bash
sort -t, -k2,2n out/testset/scores.csv | grep -v -e ERROR -e network_score | head -1   # the lowest score
.venv/bin/tool analyze "$TS" --out out/testset-ui --json --lang en "${ANALYZE_ARGS[@]}"  # same CSVs, plus JSON
.venv/bin/tool serve --result out/testset-ui/json/<that file>.json
```

Open http://127.0.0.1:8000. Take a screenshot of the home screen showing:
- the score;
- "Most dangerous device";
- "Do this first".

Save it as `"$UP/ui-screenshot.png"`, then stop the server with Ctrl+C.

The other way to get there: run `tool serve`, then use **"Open a scan file"** on the home screen and pick that file.

**Pass:** the score on screen equals that file's row in `out/testset/scores.csv`.

### 9. Upload

```bash
cmp out/testset/findings.csv out/testset-ui/findings.csv && echo same   # the --json run changed nothing
head -1 out/testset/findings.csv out/testset/scores.csv                  # file,ip,port,finding_code,severity / file,network_score
cp -r out/testset "$UP/"
```

Upload `out/testset/findings.csv`, `out/testset/scores.csv` and `$UP/ui-screenshot.png` through the submission form.

**Don't open the CSVs in Excel or Numbers.** Saving from them rewrites line ends and quoting. Upload the files exactly as `tool analyze` wrote them.

**Pass:** the form confirms the upload. Write the time down.

### 10. Tag `final` on that commit, right away

```bash
git status --porcelain                      # still nothing
git log --oneline -1                        # the same commit as step 1
git tag -a final -m "Test Set upload, $(date -u +%FT%TZ)"
git push origin final
git ls-remote --tags origin final           # pass: one line with the tag
gh issue comment 1 -R dork-hacks/bilet --body "[human:<name>] Test Set uploaded at <time>. Tagged final on <commit>. Code freeze until the jury."
```

Leave `agents:paused` on #1 until the jury sessions end. From now on the laptop stays on `final` (WORKFLOW.md §9).

### 11. Rehearse live check 1: re-run each file on its own

The jury picks one Test Set file and we re-run it live (`docs/live-checks.md`, check 1). Rehearse it now for **every** file, so no file depends on the others:

```bash
TS="$TS" UP="$UP" .venv/bin/python - "${ANALYZE_ARGS[@]}" <<'PY'
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from tool.export import scan_files

source, upload = Path(os.environ["TS"]), Path(os.environ["UP"])
flags = sys.argv[1:]
if flags not in ([], ["--all-files"]):
    raise SystemExit("Use the same empty or --all-files ANALYZE_ARGS array as the upload")
files = scan_files(source, all_files=bool(flags))
def rows(path):
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.reader(stream))

expected = {name: rows(upload / "testset" / name) for name in ("findings.csv", "scores.csv")}
if [row[0] for row in expected["scores.csv"][1:]] != [path.name for path in files]:
    raise SystemExit("Upload filenames differ from selected inputs: check ANALYZE_ARGS")
tool = str(Path(".venv/bin/tool").resolve())
with tempfile.TemporaryDirectory(prefix="bilet-rerun-") as temporary:
    root = Path(temporary)
    for path in files:
        single = root / "one"
        single.mkdir()
        shutil.copy2(path, single / path.name)
        output = root / "rerun"
        subprocess.run([tool, "analyze", str(single), "--out", str(output), "--lang", "en", *flags],
                       check=True, stdout=subprocess.DEVNULL)
        for name, records in expected.items():
            wanted = [records[0]] + [row for row in records[1:] if row[0] == path.name]
            if rows(output / name) != wanted:
                raise SystemExit(f"DIFF {path.name!r}: {name}")
        print(f"SAME {path.name!r}")
        shutil.rmtree(single)
        shutil.rmtree(output)

manifest = json.loads((upload / "testset-sha256.json").read_text())
actual = {}
for path in sorted(source.rglob("*")):
    if path.is_symlink():
        raise SystemExit("A Test Set file was replaced by a symbolic link")
    if path.is_file():
        with path.open("rb") as stream:
            actual[path.relative_to(source).as_posix()] = hashlib.file_digest(stream, "sha256").hexdigest()
if actual != manifest:
    raise SystemExit("Test Set filenames or contents changed")
print("Test Set files unchanged")
PY
```

**Pass:** one `SAME` line per selected scan input (including the extensionless broken file with `--all-files`), and `Test Set files unchanged` for **every** supplied file. CSV parsing compares exact filename fields, not regular-expression grep matches. Then run check 1 once exactly as `docs/live-checks.md` shows it, on the file you think the jury is most likely to pick: the before/after pair, or the file with the most findings.

---

## What can go wrong

| Problem | How you notice | Fix |
|---|---|---|
| **Wrong laptop** | The jury's laptop isn't the one that made the upload. | Run steps 1–11 only on the scanner laptop and take that laptop to the jury. If the upload came from another machine, re-run step 11 on the jury laptop at `final` before the session, and say honestly if anything differs. |
| **Wrong commit** | `git log --oneline -1` differs from the commit posted in #1. Or `git describe --tags` doesn't say `final` at the jury. | `git switch --detach final && make setup`. If `final` was pushed on the wrong commit, before hour 22: `git tag -f -a final <upload commit> -m …` then `git push -f origin final`, and say so in #1. |
| **Dirty tree** | `git status --porcelain` prints anything. | Uncommitted code would make the upload unreproducible from `final`. Don't upload from it. Find out what it is: `git stash` it if it's a stray edit, or commit it through a PR if it's needed. Then start again at step 1. `out/` and `data/` are git-ignored, so they don't count. |
| **Unpinned or different dependencies** | `make setup` installs something new, Python isn't 3.12, or `pip freeze` differs from `$UP/pip-freeze.txt` at the jury. | The engine needs only Python 3.12 and `defusedxml==0.7.1` (pinned in `pyproject.toml`), so CSVs don't depend on other packages. Run `make setup` on the same laptop with the same Python, and compare `pip freeze` with the saved copy. |
| **The run crashes** | A Python traceback instead of `N files, M findings, …`, so `scores.csv` isn't written. | Find the file: run `tool analyze` on each file alone, as in step 11. Open a `prio:p0` bug with the traceback and fix the crash in a PR, so the file becomes a finding or an `ERROR`. Restart at step 1. **Never edit the CSVs by hand, and never leave a file out:** the jury's re-run of that file would then not match. |
| **A readable file gives `ERROR`** | Step 6: the file looks like a complete nmap file. | Same as a crash: a `prio:p0` bug, a fix, then step 1. The parser's message in the near-miss report says where it stopped. |
| **The two runs differ** | Step 5 doesn't print `DETERMINISTIC`. | Don't upload. That's a determinism bug (NFR-05) and the re-run check would fail. Open a `prio:p0` bug with both CSVs. |
| **A file is skipped** | Step 7 lists `…: not analysed`, or the file count in step 5 is short. | Check that every supplied file was copied in step 4. Keep scan inputs at the top level and their names unchanged. Set `ANALYZE_ARGS=(--all-files)` for a visible extensionless/non-XML scan input, then repeat analysis, comparison, screenshot and per-file reruns with that array. CSV/Markdown notes and hidden files are excluded by design; ask the organizers if they identify one as a required scan input. |
| **A huge file is slow** | One file takes more than a few seconds. | Results are still right, so let it finish. The fix for files that repeat one IP thousands of times is #185 / PR #186. |
| **`out/` was deleted** | `out/testset` is missing at the jury. | `$UP/testset/` holds the uploaded copy, and step 11 compares against it. |
| **Upload form trouble** | The form refuses the files or closes. | Tell the organizers at once, with `$UP` as evidence: the CSVs, the checksums and the time. The form closes at 09:00 for everyone. |

---

## Dry run (7 Nov)

**Setup:**
- A fresh worktree of `origin/main` (`4e0d964`) plus this PR's script.
- The Validation Set's 8 XML files copied to a folder outside the repo, standing in for `$TS`.
- `$UP` a scratch folder.
- No tag was pushed: step 10 created a local tag, checked that it points at `HEAD`, and deleted it.

| Step | Result |
|---|---|
| 1 | Clean tree on `origin/main`. |
| 2 | `make setup` took 18 s. Then `ok` / `ok`, 1015 passed / 1 skipped, lint clean, Python 3.12.16. |
| 4 | 8 files, 8 checksums. |
| 5 | `8 files, 24 findings, 1 unreadable` twice, then `DETERMINISTIC`. Both runs together took 0.25 s. 8 score rows. The CSVs are byte-identical to the organizers' answer key. |
| 6 | One `ERROR`: `V7_broken.xml`, `NOT_XML: unclosed token: line 23, column 87`. Its last bytes stop inside a `<service …` tag, so it really is truncated. |
| 7 | 4 lines, all "keep": 3 × `ssl-tunnel` (V1, V5, V6b: http over SSL with a login title) and 1 × `unknown-1-port` (V4 `.99`, only 8888/tcp). 0 skipped. |
| 8 | `tool serve --result …/V4_legacy.json`. The home screen shows score 25 ("Network at risk"), the router at 192.168.1.1 as the most dangerous device, and Telnet as the first fix. |
| 9 | Headers and CRLF line ends as written. The `--json` run's CSVs equal the upload's. |
| 10 | No `final` tag on `origin` yet. A local annotated tag pointed at `HEAD`. |
| 11 | 8 × `SAME` (V1 90, V2 40, V3 45, V4 25, V5 50, V6a 60, V6b 100, V7 ERROR), then `Test Set files unchanged`. |

The near-miss report for step 7 of the dry run:

```
V1_home_basic.xml: 1 findings, score 90, 1 to check
  IP           PORT     CHECK       ENGINE      DETAIL
  192.168.1.1  443/tcp  ssl-tunnel  no finding  http over SSL, title "Router Login"

V2_smart_home.xml: 5 findings, score 40, nothing to check
…
V4_legacy.xml: 6 findings, score 25, 1 to check
  IP            PORT  CHECK           ENGINE          DETAIL
  192.168.1.99  -     unknown-1-port  UNKNOWN_DEVICE  no vendor, no hostname, only 8888/tcp sun-answerbook open
…
V7_broken.xml: ERROR (NOT_XML: ParseError: unclosed token: line 23, column 87)
  Check by hand that it really can't be read (step 6 of the runbook).

8 files, 1 unreadable, 4 items to check, 0 skipped
```
