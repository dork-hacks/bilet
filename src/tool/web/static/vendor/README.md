# Vendored front-end libraries

Served by `tool serve` from `/static/vendor/` so the web UI works offline at the venue, with no CDN and no build step (MASTERPLAN §6).

| File | Library | Version | Licence | Source | SHA-256 |
|---|---|---|---|---|---|
| `three-0.170.0.module.min.js` | [three.js](https://threejs.org/) | 0.170.0 (r170), unmodified | MIT (header kept in the file) | `https://cdn.jsdelivr.net/npm/three@0.170.0/build/three.module.min.js`, matched byte for byte against `https://unpkg.com/three@0.170.0/build/three.module.min.js` | `08fd7545d13d2c7fb65ab691530a802dafefd638596501854f267d0fb13c39e7` |

`tests/test_web_map.py` checks the hash, so a changed file fails the tests. To upgrade, download the new version from both sources, compare them, then update the file name, this table and the import in `static/netmap.js`.
