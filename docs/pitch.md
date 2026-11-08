# bilet: seven-minute pitch

Working speaker names are **teammate1–teammate5**, as requested by andrei-riciu.
Assign the demo slot to an actual junior before presenting; the placeholders do not
establish anyone's seniority. The pitch takes **6:40**, leaving **20 seconds** for
handoffs. The separate eight-minute jury checks follow [their runbook](live-checks.md).

| Time | Speaker | Part | Screen |
|---|---|---|---|
| 0:00–0:45 | teammate1 | Problem | One sentence: “Which device should I fix first?” |
| 0:45–3:00 | teammate2 (junior slot) | Demo | Recorded before → fix → after → history |
| 3:00–4:00 | teammate3 | Numbers | Validation and measured lab results |
| 4:00–5:45 | teammate4 | Trade-offs | Deterministic engine, private data, optional AI |
| 5:45–6:40 | teammate5 | Next steps and close | Limits and what comes next |
| 6:40–7:00 | All | Buffer | Hand over to the jury's live checks |

Use these as speaking prompts, not a script to memorize. Expand each point in your
own words and use the demo pauses to point at the evidence.

## 1. Problem — teammate1, 45 seconds

- Homeowners need to know **which device to fix first and what to do**.
- Scanner output is difficult for nontechnical people to interpret.
- bilet provides a priority device, clear fixing steps and a way to check progress.
- Plain Romanian and English; designed for people without networking knowledge.

## 2. Demo — teammate2, 2 minutes 15 seconds; junior slot

- Our safe “house in a box”: Raspberry Pis simulate a camera, hub and server.
- Show the recorded starting score: **25/100**, with the camera as the priority.
- Show the first recommended action and device-specific steps.
- Turn off the simulated Telnet and unencrypted administration services.
- The lab manager changes the setup; **bilet independently measures the result**.
- Show the saved result: **55/100**, with **two problems resolved** in history.
- Main journey: **scan → understand → fix → check again**.

Show these recorded images in order; do not wait for a new scan during the pitch:

1. [bilet before: 25](screenshots/155-lab-manager/09a-bilet-home-before-25-first-screen.png)
2. [Manager after two changes: expected 55](screenshots/155-lab-manager/05-after-two-fixes.png)
3. [bilet after: 55](screenshots/155-lab-manager/10a-bilet-home-after-55-first-screen.png)
4. [History: two problems resolved](screenshots/155-lab-manager/11a-bilet-history-first-screen.png)

Operator note: these are earlier recorded screens. Say “recorded lab run,” not
“live run.” Romanian screenshots predate #287's wording change; use the English
images above unless refreshed captures are available. An authorized lab operator
can demonstrate the physical sequence during the separate live checks if ready.

## 3. Numbers — teammate3, 1 minute

- **24 findings and eight score rows:** exact match to the official Validation Set CSVs.
- **Repeatable output:** the same input produces the same findings and score.
- **33 committed edge cases + one generated oversized file**, plus lab captures.
- Recorded lab scan: **269 seconds**, below the **300-second** limit; score 25.
- Lab team's recorded rehearsal: **23/23 checks passed** on an earlier build.
- These are existing measurements, not final-build or morning Test Set results.

## 4. Trade-offs — teammate4, 1 minute 45 seconds

- **Rules decide findings and scores; AI only explains.**
- Optional AI receives sanitized evidence, without IPs, MACs, hostnames or raw banners.
- Unsupported, unreadable or timed-out AI replies fall back to built-in explanations.
- Local history, masked MACs and a delete-history control.
- Live scans require confirmation and an allowed connected private network.
- Safe lab: simulated weak services, without personal data or usable remote shells.
- Limits: catalog-based checks, scanned ports only, dependence on service identification.
- **100/100 means no catalog risk detected in the scanned data, not guaranteed security.**

## 5. Next steps and close — teammate5, 55 seconds

- Test the first-action screen with more nontechnical people.
- Check the advice on more real home devices; improve coverage and service identification.
- Process the organizers' Test Set and rehearse the exact submitted build when available.
- Core value: **a clear first action, then evidence that the fix helped**.
- Hand over to the jury's live checks by seven minutes.

## Evidence ledger and rehearsal notes — not spoken

| Claim | Evidence / boundary |
|---|---|
| 24 findings, eight scores; exact official CSV match | `tests/fixtures/validation/expected_{findings,scores}.csv`; `scripts/validate.py` checks exact bytes, row order, missing/extra rows and two-run determinism. V7's score row is `ERROR`, not a successful analysis. |
| 33 committed traps + generated T26 | `tests/fixtures/traps/*.xml` (T01–T34 except T26); `make_oversized.py` generates T26 separately. These are our tests, not organizer Test Set files. |
| Lab 25 → 55, two resolved | `tests/fixtures/lab/expected_scores.csv` and the committed screenshots linked above; see [asset notes](screenshots/155-lab-manager/README.md). |
| 269 seconds, score 25, 23/23 rehearsal checks | Agent-D's hardware evidence, recorded on main `3a19d3e`, 8 Nov 00:23–00:28 UTC; summarized in [human actions](human-actions.md). Not measured by the pitch author. Do not promise the same timing with extra hotspot clients. |
| AI answers rejected | **No measured count supplied for this pitch.** If demonstrating it, read the current UI's “AI answers blocked by the safety check” counter and state the observed count and context. Do not invent a total or label every rejected answer a hallucination. |
| Final UI / full browser Check again path | #273 UI integration and #145 physical browser acceptance remain separate gates. Earlier runner acceptance is not proof of the whole browser path. |
| User acceptance | Native Romanian review and the polite-form decision are recorded in #145/#287. Testing with a real nontechnical person is still pending; do not claim it passed. |
| Morning Test Set / final build | Follow [Test Set runbook](test-set-runbook.md) and [live checks](live-checks.md). Replace no evidence with guesses. Upload and final tag remain human-only. |

Rehearse once with a stopwatch. Spend the demo pauses pointing to the result,
not navigating through menus; if running late, omit the lab-manager explanation
and move directly from 25 to 55 to history. Never consume the jury's eight-minute
check slot to finish the pitch. Confirm teammate2 is a junior, then replace the
speaker placeholders if desired. Keep the lab access code and private configuration
off screen. The lab manager is reachable on the hotspot; bilet's UI is local to
the scanner laptop, so show it there rather than promising phone access to bilet.
