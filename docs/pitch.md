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

The words below are the spoken script. Operator notes and the evidence ledger are
preparation material, not additional slides to read aloud.

## 1. Problem — teammate1, 45 seconds

“A home network can contain a camera, a printer and a smart hub, but its owner may
have no idea which one needs attention. A list of ports does not answer their real
question: which device should I fix first, and what should I do?

bilet turns a network scan into a priority, a plain-language action and a way to
check whether the fix worked. It speaks Romanian and English. Our goal is to make
the first useful action understandable to someone who is not a network engineer.
Here is that journey in our own small, controlled home network.”

## 2. Demo — teammate2, 2 minutes 15 seconds; junior slot

“These Raspberry Pis play the devices in our house: a camera, a smart hub and a
server, connected through a Pi router. The weak services are simulations. There
are no personal files or usable remote shells behind them.

This is a recorded run from that lab. bilet starts at **25 out of 100**. The camera
is the first device to fix. Instead of asking the owner to interpret a scanner
dump, we explain the problem and the action to take.

Our lab manager lets us change the fake house safely. Here we turn off Telnet and
the camera's unencrypted administration page. The manager predicts the expected
result; bilet independently scans the network to find out what actually changed.
The manager does not feed findings or scores into bilet.

After the fixes, the saved scan scores **55**. History shows the rise from 25 to
55 and the **two resolved problems**. The score is still below 100: we fixed two
things, not everything. This gives the owner a clear next action and evidence that
the previous action helped.

The same result has Romanian and English explanations and device-specific steps.
If the AI service is unavailable, these explanations still work. The important
loop is simple: find the priority, make a change, then check the result.”

Operator: show these four committed images in order, with short pauses for the
score, action and history. Do not wait for a new four-minute scan during the pitch.

1. [bilet before: 25](screenshots/155-lab-manager/09a-bilet-home-before-25-first-screen.png)
2. [Manager after two changes: expected 55](screenshots/155-lab-manager/05-after-two-fixes.png)
3. [bilet after: 55](screenshots/155-lab-manager/10a-bilet-home-after-55-first-screen.png)
4. [History: two problems resolved](screenshots/155-lab-manager/11a-bilet-history-first-screen.png)

These are earlier recorded screens, not a claim about the final UI layout. The
Romanian screenshots predate the polite-form wording change (#287); use the
English images above unless refreshed Romanian captures are available. If hardware
is ready, an authorized lab operator may demonstrate the same sequence during the
separate live checks. Do not describe recorded evidence as a new live run.

## 3. Numbers — teammate3, 1 minute

“On the organizers' Validation Set, our CSVs match the supplied answers byte for
byte: **24 findings and eight score rows**, with no missing or extra rows. Repeated
runs produce the same output. These are Validation Set results, not a claim about
the unreleased Test Set.

We also check **33 committed edge-case files**, plus a generated oversized file,
and our before-and-after lab captures. Broken or hostile files must produce a
controlled error rather than silently disappearing.

On the real hotspot, our lab team recorded a full scan in **269 seconds**, under
the 300-second limit, with score 25. Their rehearsal passed **23 out of 23 checks**.
Those are recorded measurements on an earlier build; the final build still needs
its own rehearsal. We keep the evidence separate from what we hope to achieve.”

## 4. Trade-offs — teammate4, 1 minute 45 seconds

“We made one central decision: the rules decide the findings and the score. The
AI cannot change either. The score is 100 minus the catalog's risk points, with a
floor of zero. That makes a saved scan repeatable and makes a before-and-after
comparison meaningful.

AI is optional. It can explain a result or answer a question using sanitized
evidence under device pseudonyms. It does not receive the home's IP addresses,
MAC addresses, hostnames or raw banners. We check its replies against the evidence;
if a reply fails that check, times out or cannot be read, we show our built-in
explanation. These checks reduce unsupported answers; they do not prove that an
AI can never be wrong.

History stays on the laptop, MAC addresses are masked, and the owner can delete
the saved history. A live scan needs explicit confirmation and is restricted to
the connected, allowed private network. Our demo uses only our own lab.

The trade-off is coverage. This is a catalog-based checker, not a complete security
audit. A perfect score means no catalog finding was detected in the scanned data;
it is not a guarantee that the home is secure. Unscanned ports, silent UDP services
and what the scanner cannot identify remain limitations.”

## 5. Next steps and close — teammate5, 55 seconds

“Next, we want to test the first-action screen with more people who are not
technical, check the advice across more real home devices, and improve coverage
without losing repeatability or privacy.

The immediate event steps are to process the organizers' Test Set and rehearse
the exact submitted build. Until those runs happen, we do not claim their results.

Our contribution is a complete feedback loop: an independent scan, a repeatable
score, a clear first action, and a comparison showing what improved. The fake
house lets us demonstrate that loop safely, instead of just showing a screenshot
of a scanner. bilet helps an owner move from ‘something may be wrong’ to ‘I know
what to do first.’ We are ready for your live checks.”

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
