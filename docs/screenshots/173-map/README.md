# Network explorer QA (#173)

Fixture-only Chromium checks, 7 November 2026. Desktop: 1440 × 1100;
phone: 375 × 812. Software WebGL (SwiftShader), reduced-motion preference enabled.
No real network was scanned. Device addresses/names are synthetic.

- [Desktop](desktop.png): warm neutral device models and separate inspector/search panes.
- [Phone, Romanian](phone.png): stacked panes, readable controls, no horizontal overflow.
- [Fullscreen](fullscreen.png): native fullscreen keeps inspector and directory available.
- [Selected device in a 250-device fixture](dense-selected.png): search for Device 237,
  select it, and focus its model. Ten directory rows per page, 25 pages before searching.

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
node --test tests/netmap-layout.test.mjs
uv build --wheel
```

The wheel was also installed into an isolated target and its CSS, map modules and
vendored Three.js requested successfully through FastAPI's TestClient.

The full local suite has one unrelated lab failure: the preset test expects `nmcli`
to be absent but adds `/usr/bin` to its fake-tool PATH. NetworkManager is installed
on this laptop. Reported to the lab owners on sync issue #1; application tests pass.
