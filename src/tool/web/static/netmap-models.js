// A small family of tactile, neutral devices. Risk belongs to the status light and
// plinth, so a camera still looks like a camera when its score changes.
import * as THREE from "./vendor/three-0.170.0.module.min.js";

const geometries = new Map();
const materials = new Map();
const C = { shell: 0xf7f3ed, edge: 0xd9ddd8, ink: 0x263e40, glass: 0x345f62, silver: 0xb9c8c5 };
function material(color, metalness = 0.06, roughness = 0.42) {
  const key = `${color}-${metalness}-${roughness}`;
  if (!materials.has(key)) materials.set(key, new THREE.MeshStandardMaterial({ color, metalness, roughness }));
  return materials.get(key);
}
function geometry(key, make) {
  if (!geometries.has(key)) geometries.set(key, make());
  return geometries.get(key);
}
function mesh(g, m, x, y, z) {
  const item = new THREE.Mesh(g, m);
  item.position.set(x, y, z);
  item.castShadow = true;
  item.receiveShadow = true;
  return item;
}
function block(w, h, d, color, x = 0, y = 0, z = 0, radius = 0.06) {
  const r = Math.min(radius, w / 3, h / 3, d / 3);
  const key = `box:${w}:${h}:${d}:${r}`;
  const g = geometry(key, () => {
    // Rounded boxes with shared buffers; no downloaded models or extra dependencies.
    const shape = new THREE.Shape();
    const a = w / 2 - r / 2, b = h / 2 - r / 2, c = r / 2;
    shape.moveTo(-a + c, -b);
    shape.lineTo(a - c, -b); shape.quadraticCurveTo(a, -b, a, -b + c);
    shape.lineTo(a, b - c); shape.quadraticCurveTo(a, b, a - c, b);
    shape.lineTo(-a + c, b); shape.quadraticCurveTo(-a, b, -a, b - c);
    shape.lineTo(-a, -b + c); shape.quadraticCurveTo(-a, -b, -a + c, -b);
    const result = new THREE.ExtrudeGeometry(shape, {
      depth: d - r, bevelEnabled: true, bevelSize: r / 2,
      bevelThickness: r / 2, bevelSegments: 3, steps: 1, curveSegments: 4,
    });
    result.translate(0, 0, -(d - r) / 2);
    return result;
  });
  return mesh(g, material(color), x, y, z);
}
function cylinder(radius, height, color, x = 0, y = 0, z = 0, bottom = radius) {
  return mesh(geometry(`cyl:${radius}:${height}:${bottom}`,
    () => new THREE.CylinderGeometry(radius, bottom, height, 24)), material(color), x, y, z);
}
function lens(radius, depth, color, x, y, z) {
  const item = cylinder(radius, depth, color, x, y, z);
  item.rotation.x = Math.PI / 2;
  return item;
}

export function buildModel(type, accent, compact = false) {
  const group = new THREE.Group();
  const add = (...items) => group.add(...items);
  const light = (x, y, z, w = 0.07) => block(w, 0.035, 0.025, accent, x, y, z, 0.01);
  let height = 1.4;
  switch (type) {
    case "router":
      add(block(1.8, 0.3, 1.12, C.edge, 0, 0.18), block(1.8, 0.2, 1.12, C.shell, 0, 0.36));
      for (const x of [-0.66, 0.66]) {
        const antenna = block(0.085, 1, 0.085, C.ink, x, 0.91, -0.35, 0.025);
        antenna.rotation.z = -x * 0.16; add(antenna);
      }
      add(block(0.7, 0.025, 0.28, C.silver, 0, 0.475, -0.04));
      for (let i = 0; i < 4; i++) add(light(-0.42 + i * 0.27, 0.28, 0.568));
      height = 1.5; break;
    case "camera": {
      add(cylinder(0.36, 0.11, C.edge, 0, 0.07, 0, 0.43));
      add(block(0.13, 0.54, 0.17, C.silver, 0, 0.34));
      const head = new THREE.Group();
      head.add(block(0.82, 0.65, 0.86, C.shell), block(0.68, 0.52, 0.12, C.ink, 0, 0, 0.43));
      head.add(lens(0.22, 0.07, C.silver, 0, 0, 0.52));
      head.add(lens(0.17, 0.04, C.glass, 0, 0, 0.57));
      head.add(lens(0.08, 0.045, 0x142a32, 0, 0, 0.6));
      if (!compact) head.add(lens(0.035, 0.012, 0xcfe3e3, -0.07, 0.07, 0.63));
      head.add(light(0.26, -0.15, 0.505));
      head.position.y = 0.9; head.rotation.x = -0.08; add(head);
      height = 1.3; break;
    }
    case "server":
    case "nas": {
      const server = type === "server", h = server ? 1.7 : 1.12;
      add(block(server ? 0.9 : 1.18, h, 0.9, C.shell, 0, h / 2 + 0.05));
      add(block(server ? 0.76 : 1.04, h - 0.14, 0.05, C.ink, 0, h / 2 + 0.05, 0.47));
      const slots = server ? 4 : 2;
      for (let i = 0; i < slots; i++) {
        const y = 0.28 + i * (h - 0.38) / (slots - 1);
        add(block(server ? 0.62 : 0.88, 0.16, 0.055, C.silver, 0, y, 0.51));
        add(light(0.23, y, 0.55));
      }
      height = h + 0.1; break;
    }
    case "iot_hub":
      add(cylinder(0.64, 0.12, C.edge, 0, 0.08), cylinder(0.62, 0.32, C.shell, 0, 0.28));
      add(cylinder(0.5, 0.02, C.silver, 0, 0.45), cylinder(0.08, 0.025, accent, 0, 0.47));
      height = 0.65; break;
    case "pc": {
      add(block(1.45, 0.09, 1, C.silver, 0, 0.07, 0.25));
      add(block(1.15, 0.016, 0.42, C.ink, 0, 0.12, 0.12));
      add(block(0.38, 0.015, 0.18, C.edge, 0, 0.122, 0.55));
      const screen = new THREE.Group();
      screen.add(block(1.43, 0.94, 0.09, C.ink), block(1.26, 0.76, 0.015, C.glass, 0, 0, 0.054));
      if (!compact) screen.add(block(0.75, 0.022, 0.018, C.silver, -0.12, -0.17, 0.064));
      screen.position.set(0, 0.61, -0.2); screen.rotation.x = -0.16; add(screen);
      height = 1.2; break;
    }
    case "phone": {
      const phone = new THREE.Group();
      phone.add(block(0.58, 1.12, 0.11, C.silver), block(0.5, 0.98, 0.02, C.glass, 0, 0, 0.064));
      phone.add(block(0.16, 0.04, 0.025, C.ink, 0, 0.43, 0.08), light(0, -0.4, 0.08, 0.15));
      phone.position.y = 0.67; phone.rotation.x = -0.12; add(phone);
      add(block(0.65, 0.09, 0.4, C.edge, 0, 0.06)); height = 1.3; break;
    }
    case "tv":
      add(block(1.95, 1.1, 0.12, C.ink, 0, 0.88), block(1.77, 0.91, 0.02, C.glass, 0, 0.9, 0.075));
      for (const x of [-0.63, 0.63]) add(block(0.09, 0.35, 0.35, C.silver, x, 0.18));
      add(light(0.8, 0.4, 0.08)); height = 1.5; break;
    case "printer":
      add(block(1.24, 0.5, 0.95, C.edge, 0, 0.31), block(1.27, 0.24, 0.97, C.shell, 0, 0.6));
      add(block(0.83, 0.09, 0.09, C.ink, 0, 0.37, 0.49));
      add(block(0.8, 0.035, 0.46, C.shell, 0, 0.32, 0.65));
      add(block(0.73, 0.5, 0.025, 0xffffff, 0, 0.86, -0.28));
      add(light(0.43, 0.6, 0.5)); height = 1.15; break;
    default:
      add(block(0.8, 0.82, 0.8, C.shell, 0, 0.5, 0, 0.2));
      add(block(0.25, 0.05, 0.03, accent, 0, 0.5, 0.42)); height = 1.05;
  }
  return [group, height];
}
