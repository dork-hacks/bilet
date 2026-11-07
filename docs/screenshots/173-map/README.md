# Network explorer QA (#173)

Fixture-only Chromium checks, 7 November 2026. Desktop: 1440 × 1100;
phone: 375 × 812. Additional layout assertions at 1366 × 768, 1280 × 800,
1440 × 900 and 1024 × 768 verified no clipping or horizontal overflow. Software WebGL (SwiftShader), reduced-motion preference enabled.
No real network was scanned. Device addresses/names are synthetic.

- [Desktop](desktop.png): full-width map with naturally sized device-detail and search cards below.
- [Laptop, 1366 × 768](laptop-1366.png): full information without nested panel scrollbars.
- [Phone, Romanian](phone.png): stacked panes, readable controls, no horizontal overflow.
- [Fullscreen](fullscreen.png): native fullscreen keeps inspector and directory available.
- [Selected device in a 250-device fixture](dense-selected.png): search for Device 237,
  select it, and focus its model. Ten directory rows per page, 25 pages before searching.

Toolbar shortcuts focus the detail card or search; Zoom to this device returns to the map.
Both cards grow with their content, and all ten directory rows are visible per page.

Browser assertions passed: native fullscreen enter/exit; denied-fullscreen expansion
and Escape; forward keyboard focus wrapping; row selection retains keyboard focus;
focus device; 3D/list switching; browser back; 250-device pagination/search/no matches;
selection of all ten device types; mobile fullscreen; empty/error pages; no-WebGL and
no-JavaScript list fallbacks. No page errors were emitted.

A mobile flex sizing feedback loop and startup without a URL fragment were found
and fixed during these checks. Rendering is demand-driven; this is functional QA,
not a hardware performance measurement on the Pis or a Safari/Firefox verification.

Automated checks:

```sh
.venv/bin/pytest tests
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
.venv/bin/python scripts/validate.py
make test-map
uv build --wheel
```

The wheel was also installed into an isolated target and its CSS, map modules and
vendored Three.js requested successfully through FastAPI's TestClient.

The full local suite has one unrelated lab failure: the preset test expects `nmcli`
to be absent but adds `/usr/bin` to its fake-tool PATH. NetworkManager is installed
on this laptop. Reported to the lab owners on sync issue #1; application tests pass.

Peer-review follow-up: risk words and the most-dangerous badge are restored on map
labels. The worst label remains eligible in dense mode independently of selection
(with normal clipping outside the camera view). Small networks fan out in front
of the gateway, directory rows lead with device type, and keyboard focus selects
a map label. Home-page prose retains its narrower reading width.

804 application tests and 11 Node checks passed. Accessibility tests now include
the map CSS and its gradient colours. A separate code review found a WebGL
restoration defect: 3D is now disabled during context loss and re-enabled with
a render request on restoration. Both the reviewer and a browser loss/restore
probe verified the fix. Dense worst-label visibility and keyboard-focus selection
also passed browser checks.

Final independent review caught an inherited compact-stage rule hiding risk words.
The explicit override now keeps those words visible at phone widths. Reproduce the
rendered-style regression with Playwright/Chromium installed and a local UI showing
an example scan:

```sh
python scripts/check_map_browser.py --url 'http://127.0.0.1:8000/?lang=en'
```

This checks actual computed text visibility and panel clipping at 375, 1280 and
1366 pixels; it never starts a live scan.
