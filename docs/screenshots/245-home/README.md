# Home-flow evidence (#245)

These viewport screenshots use the official `V2_smart_home.xml` fixture, AI off,
and an injected mocked runner. They contain fixture identities only. Chrome ran
with reduced motion enabled; requests were intercepted through FastAPI TestClient.
No scan, external provider or lab connection ran.

`before-{language}-{width}.png` shows main `3a19d3e` before these presentation
changes. `after-{language}-{width}.png` shows the revised home. Widths are 1366,
375 and 320 px; viewport heights are 900 px on desktop and 812 px on phones.
Screenshots deliberately show the initial viewport, with no scroll.

The home now shows saved-file context and its recorded timestamp before the score,
then the priority device, actual fixing action, steps link and Check again.
The after screenshots include the review fix: home and history share the readable
`YYYY-MM-DD HH:MM UTC` format, with the original timestamp retained in `datetime`.
The first finding is expanded; other findings use native disclosures. Device steps
come before optional plan, map and assistant disclosures. Supporting navigation
uses links, while primary, secondary and destructive actions retain distinct styles.

For English at 375 px, the document shrinks from 15,279 to 4,355 px, and Check again
moves from y=1,448 to y=742. Both languages previously overflowed at 320 px; neither
now does. At 320 px Romanian, the first action remains readable before scrolling,
but the buttons require scrolling. No claim is made that every action fits every
first viewport.

Additional Chrome checks covered both languages at all three widths: a saved error,
30 synthetic devices, history and report pages, mocked running/cancelled/failed
scan states, text size and document overflow. Interaction checks covered the direct
steps link, visible keyboard focus, hover, file-opening disclosure, assistant
pending/disabled/failure/retry behavior and retained question text. The Romanian
empty state and file-opening recovery also work with JavaScript disabled at 320 px.

The mechanical design detector reports flat type hierarchy for home/history because
it does not resolve the Jinja style include. Computed browser typography and the
existing font-size/contrast tests verify the actual shared styles. The detector
found no other warnings on the changed templates.

Pending independent review: keyboard navigation across the complete flow, visual
judgment of the final screenshots, and real hardware/browser scan behavior. The
latter requires an authorized lab runner; fixture checks are not hardware evidence.
