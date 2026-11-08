# Human actions left before the `final` tag

Agents can't do these: each one needs a person, hardware, a password or a decision. **Every agent: tell your own human the items for them, in your own session, and post on #207 once you've done it.** Times are UTC on Sunday 8 Nov unless stated otherwise. The hard deadline is the `final` tag by **08:00**: Test Set at 06:00, upload and freeze at 07:00 (WORKFLOW §9).

Who's whose human:

| Human | Agents |
|---|---|
| `@Mef05` | `agent-A`, `agent-Z` (unavailable; tasks handed to A) |
| `@edybostina` (Eduard) | `agent-B`, `agent-G` |
| `@andreea110` (Andreea) | `agent-C` |
| `@Sc1pex` | `agent-D`, `agent-F`, `agent-I` |
| `@andrei-riciu` | `agent-E`, `agent-H` |

**Physical checks:** hardware requests go to `[agent-D]` in the originating feature issue, then link the request in #1. Confirm current Sc1pex-hosted runner availability there, and include the commit, steps, expected result and evidence needed. Other agents use fixtures and mocked tests. Existing lab-scope and human-approval rules remain in force; this reminder grants no scanning permission.

## By importance

| # | Action | Who (suggested, confirm on #207) | Why | By |
|---|---|---|---|---|
| 1 | **Test Set morning**: run `docs/test-set-runbook.md` on the scanner laptop, upload `findings.csv`, `scores.csv` and the screenshot, then **tag `final` and push it**. Decide now: who runs it, who reads along, who uploads. | All humans; one owner for the laptop | 30% of the score. Nothing after the tag counts | 06:00–07:00; tag by 08:00 |
| 2 | **#34 lab captures are merged**: L1 (25) and L2 (55) are in `tests/fixtures/lab` and golden validation. Rehearse the before/after explanation from those committed captures; request a new capture only if a concrete check needs one. | Sc1pex / `agent-D`; hardware requests go to `[agent-D]` in the feature issue | Live check 6 and the own-lab deliverable; do not repeat completed capture work | Rehearse before the jury |
| 3 | **The 7 live checks are rehearsed**: 23/23 passed on the scanner laptop, 00:23–00:28 (`agent-D` on #1, main `3a19d3e`). The whole-hotspot scan scored 25 and took 269 s (NFR-07: under 300 s). Re-run only checks 1 and 6 on the `final` tag. During the jury slot, keep the hotspot to the lab plus the scanner laptop: each extra device adds about 40 s. | Sc1pex / `agent-D`; hardware requests go to `[agent-D]` in the feature issue | Don't redo a finished rehearsal; the timing margin is only about 30 s | Before the jury |
| 4 | **Check again on real hardware passed**: all four acceptance steps for #195 pass on the real lab (`agent-D` on #135, 00:52): a full run to DONE with score 25, the same result as the CLI, cancel with no nmap left, and closing the password window. The button can be used in the demo; keep `bilet scan --confirm` as the fallback. | Sc1pex / `agent-D`; hardware requests go to `[agent-D]` in the feature issue | Done; nothing to redo | Before the jury |
| 5 | **Pitch**: pick the speakers (at least two, **including a junior**), the 5 parts (problem, demo, numbers, trade-offs, next steps) and the 7-minute timing. Order item 10 (`docs/pitch.md`) needs these names. | All humans | Pitch and teamwork is 15% | Before the jury |
| 6 | **AI key on the jury laptop**: decide who holds `LLM_API_KEY`, and set it in that laptop's environment only (`set -a; . ./.env; set +a`). Never commit it. | Whoever owns the key (`@edybostina`?) | Without it, AI shows "Standard explanation" only (innovation 10%, NFR-06) | Before the jury |
| 7 | **Venue IP range** for guardrail check 4: at the venue, join its Wi-Fi briefly and run `ip route` / `netstat -rn` (or ask the organizers), then switch back to `RSH-dork_unit`. | Whoever is at the venue first | The refusal must name the real venue network | Jury morning |
| 8 | **Test the Romanian text** with a real non-technical person (home screen plus one fix), and post their reactions on #145. | Anyone with a parent or grandparent nearby | Ease of use (20%) and explanation quality (15%) | Before the freeze |
| 9 | **Lab readiness**: confirmed by the 00:28 live scan (score 25, the default lab). Confirm again only if a Pi is moved, rebooted or toggled before the jury. | Sc1pex / `agent-D` | The live demo needs the default lab; the merged #34 captures don't need redoing | Before the jury |
| 10 | **Human approval** for guardrail, sudo/nmap, lab or secrets changes. Current order16 guardrail PR is #266; review its actual current head after agent review. | Any human, in the PR | Agents may not supply their own human approval | Before merging sensitive changes |
| 11 | **MASTERPLAN §9**: tick the open questions that are answered (scanner-laptop OS, team size and seniority, LEDs/buttons, who holds the LLM key). | Any human | Docs accuracy | Low |
| 12 | **Optional**: a repo admin turns on branch protection for `main` (one approve, the three CI checks required). | Repo admin | Only the rules stop a push to `main` today | Optional |

The merged runner approval is recorded on #195/#135. This document records no new approval and does not mark unverified hardware checks complete.
