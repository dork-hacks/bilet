// Deterministic spacing, independent of WebGL. Every node gets a place; labels and
// the searchable directory decide how much detail to show at the current scale.
export function layoutNodes(count) {
  const points = [];
  let remaining = count, ring = 0;
  while (remaining > 0) {
    const radius = 3.8 + ring * 3.1;
    const capacity = Math.max(6, Math.floor(2 * Math.PI * radius / 3.3));
    const size = Math.min(remaining, capacity);
    for (let i = 0; i < size; i++) {
      // Small home networks fan out in front of the gateway, not behind it.
      const front = [0, -0.75, 0.75, -1.5, 1.5];
      const angle = count <= 5 ? Math.PI / 2 + front[i]
        : Math.PI / 2 + (i / size) * Math.PI * 2 + ring * 0.28;
      points.push({ x: Math.cos(angle) * radius, z: Math.sin(angle) * radius });
    }
    remaining -= size; ring++;
  }
  return { points, radius: Math.max(3.8, 3.8 + (ring - 1) * 3.1) };
}

export function matchesDevice(node, query) {
  const text = [node?.ip, node?.name, node?.type_label, node?.level?.label].filter(Boolean).join(" ");
  return text.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase());
}
