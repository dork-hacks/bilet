// No bundler or WebGL needed: node --test tests/netmap-layout.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { layoutNodes, matchesDevice } from '../src/tool/web/static/netmap-layout.js';

for (const count of [0, 1, 7, 12, 50, 250]) {
  test(`${count} nodes keep distinct, bounded positions without overlapping plinths`, () => {
    const { points, radius } = layoutNodes(count);
    assert.equal(points.length, count);
    assert.deepEqual(layoutNodes(count), { points, radius });
    for (const [i, point] of points.entries()) {
      assert.ok(Math.hypot(point.x, point.z) <= radius + 1e-8);
      assert.ok(Math.hypot(point.x, point.z) >= 3.8 - 1e-8);
      for (const other of points.slice(i + 1)) {
        assert.ok(Math.hypot(point.x - other.x, point.z - other.z) > 2.3);
      }
    }
  });
}

test('search finds devices by address, hostname, translated type or severity', () => {
  const device = { ip: '192.168.50.237', name: 'Office Camera', type_label: 'Cameră', level: { label: 'Risc mare' } };
  for (const query of ['50.237', '  OFFICE ', 'cameră', 'RISC MARE', '']) {
    assert.equal(matchesDevice(device, query), true);
  }
  assert.equal(matchesDevice(device, '192.168.50.238'), false);
  assert.equal(matchesDevice({ ip: '10.0.0.2' }, '10.0.0.2'), true);
});
