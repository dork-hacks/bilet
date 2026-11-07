# Human actions left before the `final` tag

Agents can't do these: each one needs a person, hardware, a password or a decision. **Every agent: tell your own human the items for them, in your own session, and post on #207 once you've done it.** Times are UTC on Sunday 8 Nov unless stated otherwise. The hard deadline is the `final` tag by **08:00**: Test Set at 06:00, upload and freeze at 07:00 (WORKFLOW §9).

Who's whose human:

| Human | Agents |
|---|---|
| `@Mef05` | `agent-A`, `agent-Z` |
| `@edybostina` (Eduard) | `agent-B` (inactive), `agent-G` |
| `@andreea110` (Andreea) | `agent-C` |
| `@Sc1pex` | `agent-D`, `agent-F` |
| `@andrei-riciu` | `agent-E`, `agent-H` |

**Lab access from home:** the Pis are reachable over the team's Tailscale network (the subnet router from #199). **Invites are per person:** one only works for the account it was made for, so it can't be forwarded. Each human who needs access asks `@Mef05` (or the tailnet's owner) in private for **their own** invite. Never paste an invite link, auth key or tailnet address into an issue, PR, commit or log. Tailscale access doesn't grant permission to scan. Scans still follow WORKFLOW §1 and MASTERPLAN §3: only the lab subnet, and only checks already authorised.

## By importance

| # | Action | Who (suggested, confirm on #207) | Why | By |
|---|---|---|---|---|
| 1 | **Test Set morning**: run `docs/test-set-runbook.md` on the scanner laptop, upload `findings.csv`, `scores.csv` and the screenshot, then **tag `final` and push it**. Decide now: who runs it, who reads along, who uploads. | All humans; one owner for the laptop | 30% of the score. Nothing after the tag counts | 06:00–07:00; tag by 08:00 |
| 2 | **#34 lab captures**: put pi2 back to the default (`sudo labctl preset camera`), then capture L1 → fix → L2 with `lab/verify`. **Approve** the lab PR (a human approve is required). | `@Sc1pex` with `agent-D` (Pis), or anyone on Tailscale with sudo on the scanner laptop | Live check 6 and the "own lab scans" deliverable | Merged before the 07:30 EET freeze (05:30 UTC) |
| 3 | **Rehearse the 7 live checks** on the scanner laptop (`docs/live-checks.md`). Time a whole-hotspot `bilet scan --confirm` (NFR-07: under 5 min), and check that the laptop's own IP doesn't show as an unknown device. | Scanner-laptop owner, plus the Pis over Tailscale | Every live check is scored on the day; NFR-07 has never been measured | Before 02:00 if possible |
| 4 | **"Check again" (PR #195) on real hardware**: the 4 steps in the PR's 21:41 comment (a full run, comparison with the CLI, cancel, closing the password window). Then say whether to merge. | `@Sc1pex` / `agent-D`, or whoever reaches the Pis on Tailscale with a desktop session | It's the §4.3 demo moment. `@Mef05`'s approve is already relayed; only the hardware check is left | Before 02:00 (the P1 cut-off) |
| 5 | **Pitch**: pick the speakers (at least two, **including a junior**), the 5 parts (problem, demo, numbers, trade-offs, next steps) and the 7-minute timing. Order item 10 (`docs/pitch.md`) needs these names. | All humans | Pitch and teamwork is 15% | Before the jury |
| 6 | **AI key on the jury laptop**: decide who holds `LLM_API_KEY`, and set it in that laptop's environment only (`set -a; . ./.env; set +a`). Never commit it. | Whoever owns the key (`@edybostina`?) | Without it, AI shows "Standard explanation" only (innovation 10%, NFR-06) | Before the jury |
| 7 | **Venue IP range** for guardrail check 4: at the venue, join its Wi-Fi briefly and run `ip route` / `netstat -rn` (or ask the organizers), then switch back to `RSH-dork_unit`. | Whoever is at the venue first | The refusal must name the real venue network | Jury morning |
| 8 | **Test the Romanian text** with a real non-technical person (home screen plus one fix), and post their reactions on #145. | Anyone with a parent or grandparent nearby | Ease of use (20%) and explanation quality (15%) | Before the freeze |
| 9 | **Lab rollout**: the two-Pi default (#128) and real daemons (#154) on the Pis; check the default lab scores 25. | `@Sc1pex` | Needed before the #34 captures | Before item 2 |
| 10 | **Human approves for order items** that touch the guardrail, the sudo/nmap path, the lab or secrets (for example order 16, the guardrail refusal order) once their PRs are up. | Any human, in the PR | Agents may not approve those | When they appear |
| 11 | **MASTERPLAN §9**: tick the open questions that are answered (scanner-laptop OS, team size and seniority, LEDs/buttons, who holds the LLM key). | Any human | Docs accuracy | Low |
| 12 | **Optional**: a repo admin turns on branch protection for `main` (one approve, the three CI checks required). | Repo admin | Only the rules stop a push to `main` today | Optional |

Done for `@Mef05`, in his name (relayed by `agent-Z`, 7 Nov 22:28 UTC): the human approve on PR #195.
