// Local-only progressive enhancement of the server-rendered device list. All scan
// strings are textContent, and no network requests or measured-traffic claims are made.
import * as THREE from "./vendor/three-0.170.0.module.min.js";
import { buildModel } from "./netmap-models.js";
import { layoutNodes, matchesDevice } from "./netmap-layout.js";

const section = document.getElementById("network-map");
const dataTag = document.getElementById("netmap-data");
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const COLOURS = { high: 0xa8322a, medium: 0x8a5300, low: 0x1d5a8a, none: 0x2e6b34 };
const ACCENT = 0x0f5c57;

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "text") node.textContent = value;
    else if (key === "className") node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) if (child) node.append(child);
  return node;
}
function webglWorks() {
  try {
    const c = document.createElement("canvas");
    const gl = c.getContext("webgl2");
    if (!gl) return false;
    gl.getExtension("WEBGL_lose_context")?.loseContext();
    return true;
  } catch { return false; }
}

function start(data) {
  const wrap = section.querySelector(".netmap-3d");
  const stage = section.querySelector(".netmap-stage");
  const detail = section.querySelector(".netmap-detail");
  const list = section.querySelector(".netmap-list");
  const switcher = section.querySelector(".netmap-switch");
  const directory = section.querySelector(".netmap-directory");
  const search = section.querySelector(".netmap-search");
  const results = section.querySelector(".netmap-results");
  const count = section.querySelector(".netmap-count");
  const previous = section.querySelector("[data-page=previous]");
  const next = section.querySelector("[data-page=next]");
  const pageInfo = section.querySelector(".netmap-page-info");
  const panelLinks = section.querySelector(".netmap-panel-links");
  const detailsShortcut = section.querySelector(".netmap-details-shortcut");
  const searchShortcut = section.querySelector(".netmap-search-shortcut");
  const fullscreen = section.querySelector(".netmap-fullscreen");
  const icons = document.getElementById("netmap-icons");
  const T = data.text;
  const layout = layoutNodes(data.nodes.length);
  const large = data.nodes.length > 32;
  let renderer, contextLost = false;
  try { renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true }); }
  catch { return; }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, large ? 1 : 1.75));
  renderer.shadowMap.enabled = !large;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.05;
  const canvas = renderer.domElement;
  canvas.setAttribute("role", "img");
  canvas.setAttribute("aria-label", T.map_canvas_label);
  stage.append(canvas);
  stage.tabIndex = 0;
  stage.setAttribute("aria-label", T.map_canvas_label);
  stage.setAttribute("aria-describedby", "map-instructions");

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 1000);
  scene.add(new THREE.HemisphereLight(0xffffff, 0xd1d8d3, 1.9));
  const sun = new THREE.DirectionalLight(0xfff4df, 2.4);
  sun.position.set(-4, 12, 7);
  sun.castShadow = !large;
  sun.shadow.mapSize.set(1024, 1024);
  const span = layout.radius + 3;
  Object.assign(sun.shadow.camera, { left: -span, right: span, top: span, bottom: -span });
  sun.shadow.normalBias = 0.035; sun.shadow.bias = -0.0003;
  sun.shadow.camera.updateProjectionMatrix(); scene.add(sun);
  const fill = new THREE.DirectionalLight(0xcce4df, 1.5);
  fill.position.set(5, 6, -4); scene.add(fill);

  const floor = new THREE.Mesh(new THREE.CircleGeometry(layout.radius + 2, 96),
    new THREE.MeshStandardMaterial({ color: 0xeeeae1, roughness: 1 }));
  floor.rotation.x = -Math.PI / 2; floor.receiveShadow = true; scene.add(floor);
  const entries = [], pickables = [], edges = [];
  const plinthGeometry = new THREE.CylinderGeometry(1.04, 1.09, 0.12, 48);
  const ringGeometry = new THREE.RingGeometry(1.06, 1.105, 48);
  const plinthMaterial = new THREE.MeshStandardMaterial({ color: 0xe0e3dc, roughness: 0.8 });

  function iconFor(kind) {
    const match = icons?.content.querySelector(`[data-kind="${CSS.escape(kind)}"]`);
    return match?.querySelector("svg")?.cloneNode(true) || null;
  }
  function chip(level) {
    return el("span", { className: `lvl lvl-${level.key}` }, [
      el("span", { "aria-hidden": "true", text: level.icon }), " ",
      el("span", { className: "lvl-word", text: level.label }),
    ]);
  }
  function addDevice(node, x, z, isHub) {
    const color = node ? COLOURS[node.level.key] : ACCENT;
    const [group, height] = buildModel(node?.type || "router", color, large);
    group.position.set(x, 0.13, z); group.rotation.y = 0.28;
    const plinth = new THREE.Mesh(plinthGeometry, plinthMaterial);
    plinth.position.set(x, 0.06, z); plinth.receiveShadow = true; scene.add(plinth);
    const ring = new THREE.Mesh(ringGeometry,
      new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.65, side: THREE.DoubleSide }));
    ring.rotation.x = -Math.PI / 2; ring.position.set(x, 0.131, z); scene.add(ring, group);
    const entry = { node, group, ring, height, pos: new THREE.Vector3(x, 0, z), isHub };
    group.traverse(m => { if (m.isMesh) { m.userData.entry = entry; pickables.push(m); } });
    entries.push(entry);
    return entry;
  }
  const hub = addDevice(data.hub, 0, 0, true);
  for (let i = 0; i < data.nodes.length; i++) {
    const { x, z } = layout.points[i];
    const entry = addDevice(data.nodes[i], x, z, false);
    const curve = new THREE.QuadraticBezierCurve3(
      new THREE.Vector3(0, 0.07, 0), new THREE.Vector3(x * 0.4 - z * 0.08, 0.07, z * 0.4),
      new THREE.Vector3(x, 0.07, z));
    const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(24)),
      new THREE.LineBasicMaterial({ color: 0x7b9691, transparent: true, opacity: 0.4 }));
    scene.add(line); edges.push({ line, entry });
  }

  let selected = null, page = 0, query = "", touched = false;
  let frameId = 0, dirty = true, visible = true, alive = true;
  const PAGE_SIZE = 10;
  const initial = { theta: 0.26, phi: 0.78, dist: 20 };
  const view = { ...initial, target: new THREE.Vector3() };
  const goal = { ...initial, target: new THREE.Vector3() };
  function jump() { Object.assign(view, { theta: goal.theta, phi: goal.phi, dist: goal.dist }); view.target.copy(goal.target); }
  function requestFrame() {
    dirty = true;
    if (alive && !frameId) frameId = requestAnimationFrame(frame);
  }
  function clampView() {
    goal.phi = Math.max(0.28, Math.min(1.25, goal.phi));
    goal.dist = Math.max(4.5, Math.min(initial.dist * 2.4, goal.dist));
  }
  function focus(entry) {
    touched = true;
    goal.target.set(entry.pos.x, 0.5, entry.pos.z);
    goal.dist = stage.clientWidth < 480 ? 8.5 : 7;
    goal.phi = 0.88;
    if (reduceMotion.matches) jump();
    requestFrame();
  }
  function showDetail(entry) {
    detail.replaceChildren();
    detail.scrollTop = 0;
    if (!entry.node) { detail.append(el("h3", { text: T.map_hub_virtual })); return; }
    const node = entry.node;
    detail.append(el("p", { className: "nm-eyebrow", text: T.map_selected }));
    const heading = el("h3", {}, [iconFor(node.type), el("span", { text: node.type_label })]);
    detail.append(heading, chip(node.level));
    if (node.worst) detail.append(el("p", { className: "nm-priority", text: T.map_most_dangerous }));
    const facts = el("dl");
    for (const [label, value] of [[T.map_name, node.name], [T.map_ip, node.ip], [T.map_mac, node.mac]]) {
      if (value) facts.append(el("dt", { text: label }), el("dd", { text: value }));
    }
    detail.append(facts);
    if (node.findings.length) {
      const findings = el("ul", { className: "nm-findings" });
      for (const f of node.findings) {
        const item = el("li", {}, [el("span", { className: "tag", text: f.severity_label }),
          el("span", { text: f.title })]);
        if (f.port) item.append(el("span", { className: "muted", text: T.port.replace("{port}", f.port) }));
        findings.append(item);
      }
      detail.append(findings);
    } else detail.append(el("p", { text: T.map_no_findings }));
    const actions = el("div", { className: "nm-detail-actions" });
    const focusButton = el("button", { type: "button", text: T.map_focus });
    focusButton.addEventListener("click", () => {
      focus(entry); stage.scrollIntoView({ block: "center", behavior: "instant" });
      stage.focus({ preventScroll: true });
    });
    // The fix steps live on /devices since #273; the section carries that page's URL.
    const link = el("a", { href: `${section.dataset.devicesUrl || ""}#${node.id}`, text: node.has_problems ? T.map_go_problems : T.map_go_device });
    link.addEventListener("click", async () => {
      if (document.fullscreenElement === section) await document.exitFullscreen();
      section.classList.remove("is-expanded"); syncFullscreen();
    });
    focusButton.className = "nm-focus-action";
    detail.insertBefore(focusButton, facts);
    actions.append(link); detail.append(actions);
  }
  function select(entry, move = false) {
    selected = entry;
    for (const e of entries) {
      e.label?.setAttribute("aria-pressed", String(e === entry));
      e.ring.scale.setScalar(e === entry ? 1.17 : 1);
      e.ring.material.opacity = e === entry ? 1 : 0.45;
    }
    for (const edge of edges) {
      edge.line.material.color.setHex(edge.entry === entry ? ACCENT : 0x7b9691);
      edge.line.material.opacity = edge.entry === entry ? 0.95 : 0.25;
    }
    detailsShortcut.textContent = entry.node
      ? `${T.map_selected}: ${entry.node.type_label}` : T.map_selected;
    showDetail(entry); renderDirectory();
    if (move) focus(entry);
    requestFrame();
  }

  // The directory is the complete keyboard route into even a 250-device network.
  // Only ten rows are mounted at once; searching never removes a device from the map.
  function renderDirectory() {
    const found = entries.filter(e => e.node && matchesDevice(e.node, query));
    const pages = Math.max(1, Math.ceil(found.length / PAGE_SIZE));
    page = Math.max(0, Math.min(page, pages - 1));
    const scrollTop = results.scrollTop;
    const activeRow = results.contains(document.activeElement) ? document.activeElement.dataset.device : null;
    results.replaceChildren();
    for (const entry of found.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)) {
      const node = entry.node;
      const row = el("button", { type: "button", className: "nm-device-row",
        "data-device": node.id, "aria-pressed": String(entry === selected),
        "aria-label": `${node.type_label}, ${node.ip}. ${node.level.label}.` }, [
        iconFor(node.type), el("span", { className: "nm-row-name" }, [
          el("strong", { text: node.type_label }), el("span", { text: node.name ? `${node.ip} · ${node.name}` : node.ip }),
        ]), el("span", { className: `nm-row-status lvl-${node.level.key}`, text: node.level.icon,
          "aria-hidden": "true" }),
      ]);
      row.addEventListener("click", () => {
        select(entry, true);
        detail.scrollIntoView({ block: "nearest", behavior: "instant" });
      });
      results.append(el("li", {}, [row]));
    }
    results.scrollTop = scrollTop;
    if (activeRow) results.querySelector(`[data-device="${CSS.escape(activeRow)}"]`)?.focus({ preventScroll: true });
    if (!found.length) results.append(el("li", { className: "nm-no-results", text: T.map_no_matches }));
    count.textContent = T.map_count.replace("{shown}", String(found.length)).replace("{total}", String(entries.filter(e => e.node).length));
    pageInfo.textContent = `${page + 1} / ${pages}`;
    previous.disabled = page === 0; next.disabled = page === pages - 1;
  }
  search.addEventListener("input", () => { query = search.value; page = 0; renderDirectory(); });
  previous.addEventListener("click", () => { page--; renderDirectory(); });
  next.addEventListener("click", () => { page++; renderDirectory(); });

  for (const entry of entries) {
    // Dense maps keep the worst device, selection and gateway eligible for labels.
    const node = entry.node;
    const label = el("button", { type: "button", className: "nm-label", "aria-pressed": "false",
      "aria-label": node ? `${node.type_label}, ${node.ip}. ${node.level.label}.` : T.map_hub_virtual }, [
      el("span", { className: "nm-status-dot", "aria-hidden": "true", text: node?.level.icon || "⌂" }),
      el("span", { className: "nm-text" }, [
        el("span", { className: "nm-type", text: node?.type_label || T.map_hub_virtual }),
        el("span", { className: "nm-address", text: node?.ip || "" }),
        node ? chip(node.level) : null,
        node?.worst ? el("span", { className: "nm-worst", text: T.map_most_dangerous }) : null,
      ]),
    ]);
    label.style.setProperty("--node-accent", `#${new THREE.Color(node ? COLOURS[node.level.key] : ACCENT).getHexString()}`);
    label.addEventListener("focus", () => { if (selected !== entry) select(entry); });
    label.addEventListener("click", () => {
      select(entry, true); detail.scrollIntoView({ block: "nearest", behavior: "instant" });
      detail.focus({ preventScroll: true });
    });
    stage.append(label); entry.label = label;
  }
  const tools = el("div", { className: "netmap-tools" });
  const zoomIn = el("button", { type: "button", text: "+", "aria-label": T.map_zoom_in });
  const zoomOut = el("button", { type: "button", text: "−", "aria-label": T.map_zoom_out });
  const reset = el("button", { type: "button", text: T.map_reset });
  tools.append(zoomIn, zoomOut, reset); stage.append(tools);
  function resetView() {
    touched = false; goal.target.set(0, 0, 0);
    Object.assign(goal, initial); if (reduceMotion.matches) jump(); requestFrame();
  }
  reset.addEventListener("click", resetView);
  function zoom(factor) { touched = true; goal.dist *= factor; clampView(); if (reduceMotion.matches) jump(); requestFrame(); }
  zoomIn.addEventListener("click", () => zoom(1 / 1.2));
  zoomOut.addEventListener("click", () => zoom(1.2));

  function syncFullscreen() {
    const expanded = document.fullscreenElement === section || section.classList.contains("is-expanded");
    fullscreen.textContent = expanded ? T.map_exit_fullscreen : T.map_fullscreen;
    fullscreen.setAttribute("aria-pressed", String(expanded));
    document.body.classList.toggle("netmap-expanded", expanded); resize();
  }
  fullscreen.addEventListener("click", async () => {
    if (document.fullscreenElement === section) await document.exitFullscreen();
    else if (section.classList.contains("is-expanded")) section.classList.remove("is-expanded");
    else {
      try {
        if (!section.requestFullscreen) throw new Error("unavailable");
        await section.requestFullscreen();
      } catch { section.classList.add("is-expanded"); }
    }
    syncFullscreen();
  });
  document.addEventListener("fullscreenchange", syncFullscreen);
  section.addEventListener("keydown", e => {
    const expanded = document.fullscreenElement === section || section.classList.contains("is-expanded");
    if (expanded && e.key === "Tab") {
      const controls = [...section.querySelectorAll('button, a[href], input, [tabindex="0"]')]
        .filter(node => !node.disabled && node.getClientRects().length);
      const first = controls[0], last = controls.at(-1);
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
    }
    if (e.key === "Escape" && section.classList.contains("is-expanded")) {
      section.classList.remove("is-expanded"); syncFullscreen(); fullscreen.focus();
    }
  });

  detailsShortcut.addEventListener("click", () => {
    detail.scrollIntoView({ block: "start", behavior: "instant" }); detail.focus({ preventScroll: true });
  });
  searchShortcut.addEventListener("click", () => {
    directory.scrollIntoView({ block: "start", behavior: "instant" }); search.focus({ preventScroll: true });
  });

  const pointers = new Map(); let downAt = null, pinch = 0, wheelZooms = false;
  stage.addEventListener("pointerleave", () => { wheelZooms = false; });
  canvas.addEventListener("pointerdown", e => {
    wheelZooms = true; canvas.setPointerCapture(e.pointerId);
    pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    downAt = { x: e.clientX, y: e.clientY };
  });
  canvas.addEventListener("pointermove", e => {
    const old = pointers.get(e.pointerId); if (!old) return;
    pointers.set(e.pointerId, { x: e.clientX, y: e.clientY }); touched = true;
    if (pointers.size === 2) {
      const [a, b] = [...pointers.values()], distance = Math.hypot(a.x - b.x, a.y - b.y);
      if (pinch && distance) goal.dist *= pinch / distance;
      pinch = distance;
    } else {
      goal.theta -= (e.clientX - old.x) * 0.008;
      if (e.pointerType === "mouse") goal.phi -= (e.clientY - old.y) * 0.006;
    }
    clampView(); jump(); requestFrame();
  });
  const raycaster = new THREE.Raycaster();
  function pick(e) {
    const r = canvas.getBoundingClientRect();
    raycaster.setFromCamera(new THREE.Vector2(2 * (e.clientX - r.left) / r.width - 1,
      1 - 2 * (e.clientY - r.top) / r.height), camera);
    const hit = raycaster.intersectObjects(pickables, false)[0];
    if (hit) {
      select(hit.object.userData.entry, true);
      detail.scrollIntoView({ block: "nearest", behavior: "instant" }); detail.focus({ preventScroll: true });
    }
  }
  canvas.addEventListener("pointerup", e => {
    const click = pointers.size === 1 && downAt && Math.hypot(e.clientX - downAt.x, e.clientY - downAt.y) < 6;
    pointers.delete(e.pointerId); pinch = 0;
    if (click) pick(e);
  });
  canvas.addEventListener("pointercancel", e => { pointers.delete(e.pointerId); pinch = 0; });
  canvas.addEventListener("wheel", e => { if (wheelZooms) { e.preventDefault(); zoom(e.deltaY > 0 ? 1.12 : 1 / 1.12); } }, { passive: false });
  stage.addEventListener("keydown", e => {
    if (e.target !== stage && e.target !== canvas) return;
    const turn = { ArrowLeft: [0.2, 0], ArrowRight: [-0.2, 0], ArrowUp: [0, -0.12], ArrowDown: [0, 0.12] }[e.key];
    if (turn) { touched = true; goal.theta += turn[0]; goal.phi += turn[1]; }
    else if (["+", "="].includes(e.key)) zoom(1 / 1.15);
    else if (["-", "_"].includes(e.key)) zoom(1.15);
    else if (["0", "Home"].includes(e.key)) resetView();
    else return;
    e.preventDefault(); clampView(); if (reduceMotion.matches) jump(); requestFrame();
  });

  function resize() {
    const w = stage.clientWidth, h = stage.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h, false); camera.aspect = w / h; camera.updateProjectionMatrix();
    const half = THREE.MathUtils.degToRad(camera.fov / 2);
    const halfWide = Math.atan(Math.tan(half) * camera.aspect);
    const reach = layout.radius + 1.6;
    initial.dist = 1.05 * Math.max(reach / Math.tan(halfWide),
      (reach * Math.cos(initial.phi) + 1.8) / Math.tan(half));
    stage.classList.toggle("compact", w < 520);
    if (!touched) { Object.assign(goal, initial); if (reduceMotion.matches) jump(); }
    requestFrame();
  }
  const point = new THREE.Vector3();
  function placeLabels() {
    const w = stage.clientWidth, h = stage.clientHeight, occupied = [];
    const ordered = [...entries].sort((a, b) => Number(!!b.node?.worst) - Number(!!a.node?.worst) || (b === selected) - (a === selected) || Number(b.isHub) - Number(a.isHub));
    for (const entry of ordered) {
      const label = entry.label;
      if (entries.length > 12 && entry !== selected && !entry.isHub && !entry.node?.worst) { label.hidden = true; continue; }
      point.set(entry.pos.x, entry.height + 0.65, entry.pos.z).project(camera);
      const x = (point.x / 2 + 0.5) * w, y = (-point.y / 2 + 0.5) * h;
      label.hidden = false;
      const width = label.offsetWidth, height = label.offsetHeight;
      const left = Math.min(Math.max(x - width / 2, 8), Math.max(8, w - width - 8));
      // Try a second label row before dropping a colliding label. This keeps
      // the gateway readable behind the larger most-dangerous-device badge.
      const candidates = [y - height, y - height - 80, y - height + 80]
        .map(top => ({ left, right: left + width, top, bottom: top + height }));
      const box = candidates.find(candidate => candidate.top >= 8 && candidate.bottom <= h - 70 &&
        !occupied.some(r => candidate.left < r.right + 4 && candidate.right > r.left - 4 && candidate.top < r.bottom + 4 && candidate.bottom > r.top - 4));
      const outside = point.z > 1 || point.z < -1 || x < 0 || x > w;
      label.hidden = outside || !box;
      if (!label.hidden) { label.style.transform = `translate(${Math.round(left)}px, ${Math.round(box.top)}px)`; occupied.push(box); }
    }
  }
  function frame() {
    frameId = 0;
    if (!alive || !visible || document.hidden || wrap.hidden) return;
    const moving = Math.abs(view.dist - goal.dist) + Math.abs(view.theta - goal.theta) +
      Math.abs(view.phi - goal.phi) + view.target.distanceTo(goal.target) > 0.004;
    if (reduceMotion.matches || !moving) jump();
    else {
      view.dist += (goal.dist - view.dist) * 0.17;
      view.theta += (goal.theta - view.theta) * 0.17;
      view.phi += (goal.phi - view.phi) * 0.17;
      view.target.lerp(goal.target, 0.17);
    }
    if (!dirty && !moving) return;
    dirty = false;
    camera.position.set(view.target.x + view.dist * Math.sin(view.phi) * Math.sin(view.theta),
      view.target.y + view.dist * Math.cos(view.phi),
      view.target.z + view.dist * Math.sin(view.phi) * Math.cos(view.theta));
    camera.lookAt(view.target); renderer.render(scene, camera); placeLabels();
    if (moving) requestFrame();
  }
  const resizeObserver = new ResizeObserver(resize); resizeObserver.observe(stage);
  const intersection = new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; if (visible) requestFrame(); });
  intersection.observe(stage);
  const motionChange = () => { jump(); requestFrame(); };
  reduceMotion.addEventListener("change", motionChange);
  const visibilityChange = () => { if (!document.hidden) requestFrame(); };
  document.addEventListener("visibilitychange", visibilityChange);
  const threeButton = switcher.querySelector('[data-view="3d"]');
  canvas.addEventListener("webglcontextlost", e => {
    e.preventDefault(); contextLost = true; threeButton.disabled = true; show("list");
  });
  canvas.addEventListener("webglcontextrestored", () => {
    contextLost = false; threeButton.disabled = false; requestFrame();
  });
  function show(mode) {
    if (mode === "3d" && contextLost) return;
    wrap.hidden = mode !== "3d"; list.hidden = mode === "3d";
    fullscreen.hidden = mode !== "3d"; panelLinks.hidden = mode !== "3d";
    for (const b of switcher.querySelectorAll("[data-view]")) b.setAttribute("aria-pressed", String(b.dataset.view === mode));
    if (mode === "3d") { resize(); requestFrame(); }
    else {
      section.classList.remove("is-expanded");
      if (document.fullscreenElement === section) document.exitFullscreen().catch(() => {});
      syncFullscreen();
    }
  }
  for (const b of switcher.querySelectorAll("[data-view]")) b.addEventListener("click", () => show(b.dataset.view));
  // Rendering stops when the scene settles. No perpetual traffic simulation or pulse.
  window.addEventListener("pageshow", () => requestFrame());
  window.addEventListener("pagehide", event => {
    if (event.persisted) return;
    alive = false; cancelAnimationFrame(frameId); resizeObserver.disconnect(); intersection.disconnect();
    reduceMotion.removeEventListener("change", motionChange);
    document.removeEventListener("visibilitychange", visibilityChange);
    document.removeEventListener("fullscreenchange", syncFullscreen);
    const gs = new Set(), ms = new Set();
    scene.traverse(o => { if (o.geometry) gs.add(o.geometry); for (const m of o.material ? [o.material].flat() : []) ms.add(m); });
    for (const g of gs) g.dispose(); for (const m of ms) m.dispose(); renderer.dispose();
  });
  switcher.hidden = false; directory.hidden = false;
  show("3d"); jump(); select(entries.find(e => e.node?.worst) || hub);
}

function openTarget() {
  let target;
  try { target = location.hash ? document.getElementById(decodeURIComponent(location.hash.slice(1))) : null; }
  catch { return; }
  const box = target?.closest("details");
  if (box && !box.open) { box.open = true; target.scrollIntoView(); }
}
if (section && dataTag) {
  window.addEventListener("hashchange", openTarget); openTarget();
  let data;
  try { data = JSON.parse(dataTag.textContent); } catch { data = null; }
  if (data && webglWorks()) start(data);
}
