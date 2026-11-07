// The home screen's 3D network map (#170), in the spirit of Cisco Packet Tracer: the
// router in the middle, every device linked to it by a cable, each one drawn by its type
// and coloured by its worst problem.
//
// Progressive enhancement: the page already has the same map as a plain list. This script
// only adds the 3D view on top when WebGL works, and a switch back to the list. All text
// comes from the page's JSON (built by tool.web.map_view) and is written with textContent,
// never as HTML: hostnames are attacker-controlled (NFR-03).
import * as THREE from "./vendor/three-0.170.0.module.min.js";

const section = document.getElementById("network-map");
const dataTag = document.getElementById("netmap-data");
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

// Level colours: the same hues as the chips in _style.html, a little lighter for 3D.
const LEVEL_COLOURS = {
  high: 0xc4473d,
  medium: 0xc98a1e,
  low: 0x3f7fb5,
  none: 0x4f9a58,
};
const CHIP_COLOURS = { high: 0xa8322a, medium: 0x8a5300, low: 0x1d5a8a, none: 0x2e6b34 };
const HUB_NEUTRAL = 0x0f5c57;
const DARK = 0x2b2420;
const LIGHT = 0xf4efe8;

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
    const canvas = document.createElement("canvas");
    return !!(window.WebGLRenderingContext &&
      (canvas.getContext("webgl2") || canvas.getContext("webgl")));
  } catch {
    return false;
  }
}

// ---- device models: simple shapes from primitives, one per device type -------------------

function mat(colour, opts = {}) {
  return new THREE.MeshStandardMaterial({ color: colour, roughness: 0.55, metalness: 0.05, ...opts });
}

function box(w, h, d, material, x = 0, y = 0, z = 0) {
  const mesh = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), material);
  mesh.position.set(x, y, z);
  return mesh;
}

function cyl(rt, rb, h, material, x = 0, y = 0, z = 0, seg = 24) {
  const mesh = new THREE.Mesh(new THREE.CylinderGeometry(rt, rb, h, seg), material);
  mesh.position.set(x, y, z);
  return mesh;
}

// Builds the model for `type` in `colour`. The model faces +z; the caller turns it to
// face the router. Returns [group, height].
function buildModel(type, colour) {
  const g = new THREE.Group();
  const body = mat(colour);
  const dark = mat(DARK, { roughness: 0.4 });
  const light = mat(LIGHT);
  let height = 1;
  switch (type) {
    case "router": {
      g.add(box(1.7, 0.36, 1.05, body, 0, 0.18, 0));
      g.add(cyl(0.05, 0.05, 0.9, dark, -0.6, 0.75, -0.35));
      g.add(cyl(0.05, 0.05, 0.9, dark, 0.6, 0.75, -0.35));
      for (let i = 0; i < 4; i++) g.add(box(0.1, 0.06, 0.02, light, -0.45 + i * 0.3, 0.2, 0.53));
      height = 1.25;
      break;
    }
    case "camera": {
      g.add(cyl(0.35, 0.42, 0.12, dark, 0, 0.06, 0));
      g.add(cyl(0.07, 0.07, 0.55, dark, 0, 0.38, 0));
      const head = new THREE.Group();
      head.add(box(0.6, 0.5, 1.0, body));
      head.add(cyl(0.2, 0.2, 0.18, dark, 0, 0, 0.56).rotateX(Math.PI / 2));
      head.add(cyl(0.12, 0.12, 0.02, mat(0x5a8bb0, { metalness: 0.4 }), 0, 0, 0.66).rotateX(Math.PI / 2));
      head.position.set(0, 0.85, 0);
      head.rotation.x = 0.25;
      g.add(head);
      height = 1.2;
      break;
    }
    case "server":
    case "nas": {
      const tall = type === "server" ? 1.5 : 1.0;
      g.add(box(0.8, tall, 1.0, body, 0, tall / 2, 0));
      const slots = type === "server" ? 4 : 2;
      for (let i = 0; i < slots; i++) {
        g.add(box(0.6, 0.06, 0.02, dark, 0, 0.25 + i * (tall - 0.4) / Math.max(1, slots - 1), 0.51));
        g.add(box(0.06, 0.06, 0.02, light, 0.32, 0.25 + i * (tall - 0.4) / Math.max(1, slots - 1), 0.51));
      }
      height = tall;
      break;
    }
    case "iot_hub": {
      g.add(cyl(0.6, 0.65, 0.35, body, 0, 0.175, 0, 40));
      const dome = new THREE.Mesh(new THREE.SphereGeometry(0.58, 32, 16, 0, Math.PI * 2, 0, Math.PI / 2), light);
      dome.position.y = 0.35;
      g.add(dome);
      g.add(new THREE.Mesh(new THREE.TorusGeometry(0.6, 0.04, 8, 48), dark).rotateX(Math.PI / 2).translateZ(-0.35));
      height = 1.0;
      break;
    }
    case "pc": {
      g.add(box(1.4, 0.9, 0.08, body, 0, 0.95, 0));
      g.add(box(1.25, 0.75, 0.02, dark, 0, 0.95, 0.05));
      g.add(cyl(0.06, 0.06, 0.45, dark, 0, 0.35, -0.05));
      g.add(box(0.6, 0.06, 0.4, dark, 0, 0.03, 0));
      height = 1.45;
      break;
    }
    case "phone": {
      g.add(box(0.7, 0.12, 0.5, dark, 0, 0.06, 0));
      const phone = box(0.5, 0.95, 0.07, body, 0, 0.6, 0);
      phone.rotation.x = -0.2;
      g.add(phone);
      height = 1.1;
      break;
    }
    case "tv": {
      g.add(box(1.8, 1.05, 0.08, body, 0, 0.75, 0));
      g.add(box(1.65, 0.92, 0.02, dark, 0, 0.75, 0.05));
      g.add(box(0.1, 0.25, 0.3, dark, -0.6, 0.12, 0));
      g.add(box(0.1, 0.25, 0.3, dark, 0.6, 0.12, 0));
      height = 1.3;
      break;
    }
    case "printer": {
      g.add(box(1.1, 0.55, 0.85, body, 0, 0.275, 0));
      g.add(box(0.75, 0.4, 0.04, light, 0, 0.7, -0.25).rotateX(-0.2));
      g.add(box(0.8, 0.05, 0.3, dark, 0, 0.35, 0.44));
      height = 1.0;
      break;
    }
    default: {
      const ball = new THREE.Mesh(new THREE.IcosahedronGeometry(0.55, 1), body);
      ball.position.y = 0.6;
      g.add(ball);
      height = 1.2;
    }
  }
  g.traverse((m) => {
    if (m.isMesh) { m.castShadow = true; m.receiveShadow = true; }
  });
  return [g, height];
}

// ---- the map ----------------------------------------------------------------------------

function start(data) {
  const wrap3d = section.querySelector(".netmap-3d");
  const stage = section.querySelector(".netmap-stage");
  const detail = section.querySelector(".netmap-detail");
  const list = section.querySelector(".netmap-list");
  const switcher = section.querySelector(".netmap-switch");
  const icons = document.getElementById("netmap-icons");
  const T = data.text;

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  } catch {
    return; // no WebGL after all: the list stays
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  const canvas = renderer.domElement;
  canvas.setAttribute("role", "img");
  canvas.setAttribute("aria-label", T.map_canvas_label);
  stage.append(canvas);
  stage.setAttribute("tabindex", "0");
  stage.setAttribute("aria-label", T.map_canvas_label);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 200);
  scene.add(new THREE.HemisphereLight(0xfffaf0, 0xb8a58c, 1.6));
  const sun = new THREE.DirectionalLight(0xffffff, 1.6);
  sun.position.set(6, 12, 8);
  sun.castShadow = true;
  sun.shadow.mapSize.set(1024, 1024);
  Object.assign(sun.shadow.camera, { left: -14, right: 14, top: 14, bottom: -14 });
  scene.add(sun);

  // Devices go round the router. The most dangerous one (first in the data) faces the
  // camera, the rest are spread evenly, so the layout is the same on every load.
  const nodes = data.nodes;
  const radius = Math.max(4.2, nodes.length * 0.85);
  const floor = new THREE.Mesh(
    new THREE.CircleGeometry(radius + 2.2, 64),
    mat(0xf1e6d6, { roughness: 0.95 }),
  );
  floor.rotation.x = -Math.PI / 2;
  floor.receiveShadow = true;
  scene.add(floor);
  for (const r of [radius * 0.5, radius]) {
    const ring = new THREE.Mesh(
      new THREE.RingGeometry(r - 0.02, r + 0.02, 96),
      new THREE.MeshBasicMaterial({ color: 0xd9c9b2 }),
    );
    ring.rotation.x = -Math.PI / 2;
    ring.position.y = 0.005;
    scene.add(ring);
  }

  const entries = []; // { node, group, pos, height, label, ring, isHub }
  const pickables = [];

  function addDevice(node, pos, isHub) {
    const colour = node ? LEVEL_COLOURS[node.level.key] : HUB_NEUTRAL;
    const [group, height] = buildModel(node ? node.type : "router", colour);
    group.position.copy(pos);
    // Devices face away from the router, towards whoever looks at the map.
    if (!isHub) group.lookAt(pos.x * 2, 0, pos.z * 2);
    group.scale.setScalar(isHub ? 1.25 : 1);
    scene.add(group);
    const ring = new THREE.Mesh(
      new THREE.RingGeometry(0.95, 1.15, 48),
      new THREE.MeshBasicMaterial({
        color: node ? CHIP_COLOURS[node.level.key] : HUB_NEUTRAL, transparent: true, opacity: 0.85,
      }),
    );
    ring.rotation.x = -Math.PI / 2;
    ring.position.set(pos.x, 0.01, pos.z);
    ring.scale.setScalar(isHub ? 1.35 : 1);
    scene.add(ring);
    const entry = { node, group, pos, height: height * (isHub ? 1.25 : 1), ring, isHub };
    group.traverse((m) => { if (m.isMesh) { m.userData.entry = entry; pickables.push(m); } });
    entries.push(entry);
    return entry;
  }

  const hubEntry = addDevice(data.hub, new THREE.Vector3(0, 0, 0), true);
  const cables = [];
  // The first node sits in front, the next ones alternate right and left of it, at most
  // about 63 degrees apart: a few devices fan out in front of the router instead of
  // hiding behind it, and many devices still close the full circle.
  const step = Math.min((Math.PI * 2) / Math.max(1, nodes.length), 1.1);
  nodes.forEach((node, i) => {
    const slot = i === 0 ? 0 : Math.ceil(i / 2) * (i % 2 ? 1 : -1);
    const angle = Math.PI / 2 - slot * step;
    const pos = new THREE.Vector3(Math.cos(angle) * radius, 0, Math.sin(angle) * radius);
    // The most dangerous device starts in front: +z points at the camera's start.
    const entry = addDevice(node, pos, false);
    const curve = new THREE.QuadraticBezierCurve3(
      new THREE.Vector3(0, 0.3, 0),
      new THREE.Vector3(pos.x / 2, 0.9, pos.z / 2),
      new THREE.Vector3(pos.x, 0.3, pos.z),
    );
    const cable = new THREE.Mesh(
      new THREE.TubeGeometry(curve, 40, node.level.key === "none" ? 0.045 : 0.07, 8),
      mat(CHIP_COLOURS[node.level.key], { roughness: 0.7 }),
    );
    cable.castShadow = true;
    scene.add(cable);
    const packet = new THREE.Mesh(
      new THREE.SphereGeometry(0.12, 16, 8),
      new THREE.MeshBasicMaterial({ color: 0xffffff }),
    );
    packet.visible = false;
    scene.add(packet);
    cables.push({ curve, packet, offset: i / Math.max(1, nodes.length), entry });
  });

  // ---- labels: one real button per device, laid over the canvas -----------------------

  function iconFor(kind) {
    const holder = icons && icons.content.querySelector(`[data-kind="${CSS.escape(kind)}"]`);
    const fallback = icons && icons.content.querySelector('[data-kind="unknown"]');
    const svg = (holder || fallback)?.querySelector("svg");
    return svg ? svg.cloneNode(true) : null;
  }

  function chip(level) {
    const span = el("span", { className: `lvl lvl-${level.key}` });
    span.append(
      el("span", { "aria-hidden": "true", text: level.icon }),
      " ",
      el("span", { className: "lvl-word", text: level.label }),
    );
    return span;
  }

  for (const entry of entries) {
    const node = entry.node;
    const button = el("button", { type: "button", className: "nm-label", "aria-pressed": "false" });
    if (node) {
      button.classList.add(`lvl-${node.level.key}-b`);
      const text = el("span", { className: "nm-text" }, [
        el("span", { className: "nm-type", text: node.type_label }),
        chip(node.level),
        node.worst ? el("span", { className: "worst", text: T.map_most_dangerous }) : null,
      ]);
      button.append(iconFor(node.type) || "", text);
      // The button's name: what a screen reader says on focus.
      button.setAttribute(
        "aria-label",
        `${node.type_label}, ${node.ip}. ${node.level.label}.` +
          (node.worst ? ` ${T.map_most_dangerous}.` : ""),
      );
    } else {
      button.append(iconFor("router") || "", el("span", { className: "nm-type", text: T.map_hub_virtual }));
    }
    button.addEventListener("click", () => select(entry, true));
    button.addEventListener("focus", () => select(entry, false));
    stage.append(button);
    entry.label = button;
  }

  const tools = el("div", { className: "netmap-tools" });
  const zoomIn = el("button", { type: "button", text: "+", "aria-label": T.map_zoom_in });
  const zoomOut = el("button", { type: "button", text: "−", "aria-label": T.map_zoom_out });
  const reset = el("button", { type: "button", text: T.map_reset });
  tools.append(zoomIn, zoomOut, reset);
  stage.append(tools);

  // ---- details panel ------------------------------------------------------------------

  function showDetail(entry) {
    const node = entry.node;
    detail.replaceChildren();
    if (!node) {
      detail.append(el("h3", { text: T.map_hub_virtual }));
      return;
    }
    const heading = el("h3");
    heading.append(iconFor(node.type) || "", node.type_label, " ", chip(node.level));
    if (node.worst) heading.append(el("span", { className: "worst", text: T.map_most_dangerous }));
    detail.append(heading);
    const facts = el("dl");
    const fact = (label, value) => {
      if (value) facts.append(el("dt", { text: label }), el("dd", { text: value }));
    };
    fact(T.map_name, node.name);
    fact(T.map_ip, node.ip);
    fact(T.map_mac, node.mac);
    detail.append(facts);
    if (node.findings.length) {
      const ul = el("ul");
      for (const f of node.findings) {
        const li = el("li", { className: `sev-${f.severity}` });
        li.append(el("span", { className: "tag", text: f.severity_label }), " ", f.title);
        if (f.port) li.append(el("span", { className: "muted", text: ` · ${T.port.replace("{port}", f.port)}` }));
        ul.append(li);
      }
      detail.append(ul);
    } else {
      detail.append(el("p", { text: T.map_no_findings }));
    }
    detail.append(
      el("p", {}, [
        el("a", {
          href: `#${node.id}`,
          text: node.has_problems ? T.map_go_problems : T.map_go_device,
        }),
      ]),
    );
  }

  // ---- camera: a simple orbit around the selected device ------------------------------

  // The starting view; resize() fits it to the stage's shape.
  const START = { theta: 0, phi: 1.0, dist: radius * 2.6 + 4 };
  let touched = false; // the person moved the map: a resize no longer refits it
  const view = { ...START, target: new THREE.Vector3() };
  const goal = { ...START, target: new THREE.Vector3() };
  let selected = null;
  let needsRender = true;

  function clampView(v) {
    v.phi = Math.min(1.35, Math.max(0.3, v.phi));
    v.dist = Math.min(radius * 5 + 10, Math.max(4, v.dist));
  }

  // Focus (keyboard) shows the details; a click also turns the map towards the device.
  function select(entry, moveCamera) {
    if (selected !== entry) {
      selected = entry;
      for (const e of entries) {
        e.label.setAttribute("aria-pressed", e === entry ? "true" : "false");
        e.ring.scale.setScalar((e.isHub ? 1.35 : 1) * (e === entry ? 1.3 : 1));
      }
      showDetail(entry);
    }
    if (moveCamera) {
      touched = true;
      goal.target.set(entry.pos.x * 0.6, 0, entry.pos.z * 0.6);
      if (!entry.isHub) {
        // The shortest way round, so the map never spins a full turn.
        const want = Math.atan2(entry.pos.x, entry.pos.z);
        goal.theta += Math.atan2(Math.sin(want - goal.theta), Math.cos(want - goal.theta));
      }
      if (reduceMotion.matches) jump();
    }
    needsRender = true;
  }

  function jump() {
    view.theta = goal.theta;
    view.phi = goal.phi;
    view.dist = goal.dist;
    view.target.copy(goal.target);
  }

  function resetView() {
    touched = false;
    Object.assign(goal, { theta: START.theta, phi: START.phi, dist: START.dist });
    goal.target.set(0, 0, 0);
    if (reduceMotion.matches) jump();
    needsRender = true;
  }
  reset.addEventListener("click", resetView);
  function zoom(factor) {
    touched = true;
    goal.dist *= factor;
    clampView(goal);
    if (reduceMotion.matches) jump();
    needsRender = true;
  }
  zoomIn.addEventListener("click", () => zoom(1 / 1.2));
  zoomOut.addEventListener("click", () => zoom(1.2));

  function placeCamera() {
    const { theta, phi, dist, target } = view;
    camera.position.set(
      target.x + dist * Math.sin(phi) * Math.sin(theta),
      target.y + dist * Math.cos(phi),
      target.z + dist * Math.sin(phi) * Math.cos(theta),
    );
    camera.lookAt(target);
  }

  // Mouse and touch: drag to turn, wheel or pinch to zoom. One-finger vertical swipes keep
  // scrolling the page (touch-action: pan-y), so the map never traps someone scrolling.
  const pointers = new Map();
  let pinchStart = 0;
  let downAt = null;
  // The wheel zooms only once the person has pressed on the map, so scrolling the page
  // past it never zooms by surprise. Leaving the map gives the wheel back to the page.
  let wheelZooms = false;
  stage.addEventListener("pointerleave", () => { wheelZooms = false; });
  canvas.addEventListener("pointerdown", (e) => {
    wheelZooms = true;
    pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    canvas.setPointerCapture(e.pointerId);
    downAt = { x: e.clientX, y: e.clientY };
    if (pointers.size === 2) {
      const [a, b] = [...pointers.values()];
      pinchStart = Math.hypot(a.x - b.x, a.y - b.y);
    }
  });
  canvas.addEventListener("pointermove", (e) => {
    const prev = pointers.get(e.pointerId);
    if (!prev) return;
    const now = { x: e.clientX, y: e.clientY };
    pointers.set(e.pointerId, now);
    if (pointers.size === 2) {
      const [a, b] = [...pointers.values()];
      const d = Math.hypot(a.x - b.x, a.y - b.y);
      if (pinchStart > 0) goal.dist *= pinchStart / d;
      pinchStart = d;
    } else {
      touched = true;
      goal.theta -= (now.x - prev.x) * 0.008;
      if (e.pointerType === "mouse") goal.phi -= (now.y - prev.y) * 0.006;
    }
    clampView(goal);
    jump(); // direct manipulation follows the hand, with or without motion
    needsRender = true;
  });
  const release = (e) => {
    pointers.delete(e.pointerId);
    if (pointers.size < 2) pinchStart = 0;
  };
  canvas.addEventListener("pointerup", (e) => {
    const moved = downAt ? Math.hypot(e.clientX - downAt.x, e.clientY - downAt.y) : 99;
    release(e);
    if (moved < 6) pick(e);
  });
  canvas.addEventListener("pointercancel", release);
  canvas.addEventListener("wheel", (e) => {
    if (!wheelZooms) return;
    e.preventDefault();
    zoom(e.deltaY > 0 ? 1.12 : 1 / 1.12);
  }, { passive: false });

  const raycaster = new THREE.Raycaster();
  function pick(e) {
    const rect = canvas.getBoundingClientRect();
    const ndc = new THREE.Vector2(
      ((e.clientX - rect.left) / rect.width) * 2 - 1,
      -((e.clientY - rect.top) / rect.height) * 2 + 1,
    );
    raycaster.setFromCamera(ndc, camera);
    const hit = raycaster.intersectObjects(pickables, false)[0];
    if (hit) {
      select(hit.object.userData.entry, true);
      hit.object.userData.entry.label.focus({ preventScroll: true });
    }
  }

  // Keyboard, on the stage: arrows turn, + and - zoom, 0 resets.
  stage.addEventListener("keydown", (e) => {
    const step = { ArrowLeft: [0.2, 0], ArrowRight: [-0.2, 0], ArrowUp: [0, -0.12], ArrowDown: [0, 0.12] }[e.key];
    if (step) {
      touched = true;
      goal.theta += step[0];
      goal.phi += step[1];
    } else if (e.key === "+" || e.key === "=") goal.dist /= 1.15;
    else if (e.key === "-" || e.key === "_") goal.dist *= 1.15;
    else if (e.key === "0" || e.key === "Home") resetView();
    else return;
    e.preventDefault();
    clampView(goal);
    if (reduceMotion.matches) jump();
    needsRender = true;
  });

  // ---- size, labels and the frame loop -------------------------------------------------

  function resize() {
    const w = stage.clientWidth;
    const h = stage.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    // Fit the starting view: tall phone screens look more from above, and the camera
    // stands just far enough back for the whole ring of devices to fit.
    START.phi = camera.aspect < 1 ? 0.6 : 1.0;
    const half = THREE.MathUtils.degToRad(camera.fov / 2);
    const halfWide = Math.atan(Math.tan(half) * camera.aspect);
    const reach = radius + 1.1;
    START.dist = 1.08 * Math.max(
      reach / Math.tan(halfWide),
      (reach * Math.cos(START.phi) + 1.5) / Math.tan(half),
    );
    if (!touched) {
      Object.assign(goal, { theta: START.theta, phi: START.phi, dist: START.dist });
      if (reduceMotion.matches) jump();
    }
    // Small maps get small labels: the device icon and the level's sign (the legend says
    // what each sign means), and the full text on press. The button's name keeps it all.
    stage.classList.toggle("compact", w < 520);
    needsRender = true;
  }
  new ResizeObserver(resize).observe(stage);

  const tmp = new THREE.Vector3();
  function placeLabels() {
    const w = stage.clientWidth;
    const h = stage.clientHeight;
    const camDir = new THREE.Vector3();
    camera.getWorldDirection(camDir);
    for (const e of entries) {
      tmp.set(e.pos.x, e.height + 0.35, e.pos.z).project(camera);
      const x = (tmp.x * 0.5 + 0.5) * w;
      const y = (-tmp.y * 0.5 + 0.5) * h;
      const visible = tmp.z < 1 && x > -40 && x < w + 40 && y > -40 && y < h + 40;
      e.label.style.visibility = visible ? "visible" : "hidden";
      // Centred above the device, but always kept whole inside the map.
      const lw = e.label.offsetWidth;
      const lh = e.label.offsetHeight;
      const left = Math.min(Math.max(x - lw / 2, 4), Math.max(4, w - lw - 4));
      const top = Math.min(Math.max(y - lh, 4), Math.max(4, h - lh - 4));
      e.label.style.transform = `translate(${Math.round(left)}px, ${Math.round(top)}px)`;
      // Labels nearer the camera sit on top; the far side of the map is a little faded.
      const depth = camera.position.distanceTo(e.pos);
      e.label.style.zIndex = String(1000 - Math.round(depth * 10));
      e.label.dataset.behind = String(tmp.subVectors(e.pos, view.target).dot(camDir) > radius * 0.6);
    }
  }

  function ease(a, b, k) { return a + (b - a) * k; }

  let last = performance.now();
  let visibleOnScreen = true;
  new IntersectionObserver(([entry]) => { visibleOnScreen = entry.isIntersecting; }).observe(stage);

  function frame(now) {
    requestAnimationFrame(frame);
    const dt = Math.min(0.05, (now - last) / 1000);
    last = now;
    if (!visibleOnScreen || document.hidden || wrap3d.hidden) return;
    const moving = !reduceMotion.matches;
    if (moving) {
      const k = 1 - Math.pow(0.001, dt);
      view.theta = ease(view.theta, goal.theta, k);
      view.phi = ease(view.phi, goal.phi, k);
      view.dist = ease(view.dist, goal.dist, k);
      view.target.lerp(goal.target, k);
      // Little packets run along each cable, like Packet Tracer's simulation mode.
      const t = (now / 2600) % 1;
      for (const c of cables) {
        c.packet.visible = true;
        c.curve.getPoint((t + c.offset) % 1, c.packet.position);
      }
      // The most dangerous device's ring breathes gently.
      for (const e of entries) {
        if (e.node && e.node.worst) {
          e.ring.material.opacity = 0.55 + 0.4 * (0.5 + 0.5 * Math.sin(now / 420));
        }
      }
      needsRender = true;
    } else {
      for (const c of cables) c.packet.visible = false;
      for (const e of entries) e.ring.material.opacity = 0.85;
    }
    if (!needsRender) return;
    needsRender = false;
    placeCamera();
    renderer.render(scene, camera);
    placeLabels();
  }

  // ---- the 3D / list switch -----------------------------------------------------------

  function show(mode) {
    const is3d = mode === "3d";
    wrap3d.hidden = !is3d;
    list.hidden = is3d;
    for (const b of switcher.querySelectorAll("button")) {
      b.setAttribute("aria-pressed", b.dataset.view === mode ? "true" : "false");
    }
    if (is3d) { resize(); needsRender = true; }
  }
  for (const b of switcher.querySelectorAll("button")) {
    b.addEventListener("click", () => show(b.dataset.view));
  }
  reduceMotion.addEventListener?.("change", () => { jump(); needsRender = true; });

  switcher.hidden = false;
  show("3d");
  // A gentle fly-in when motion is allowed; with reduced motion the map just appears.
  if (!reduceMotion.matches) view.dist = START.dist * 1.6;
  placeCamera();
  requestAnimationFrame(frame);
}

// A link to a device in the "devices with no problems" list opens that list first.
function openTarget() {
  const target = location.hash && document.getElementById(decodeURIComponent(location.hash.slice(1)));
  const box = target && target.closest("details");
  if (box && !box.open) {
    box.open = true;
    target.scrollIntoView();
  }
}

if (section && dataTag) {
  window.addEventListener("hashchange", openTarget);
  openTarget();
  let data = null;
  try {
    data = JSON.parse(dataTag.textContent);
  } catch {
    data = null;
  }
  if (data && webglWorks()) start(data);
}
