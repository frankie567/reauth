const { test } = require('node:test');
const assert = require('node:assert/strict');
const { canvasBounds, constrain, snap, stackAbove, moveStack, stackOffsets, compareDepth } = require('../../docs/javascripts/bricks.js');

test('snaps above and below a nearby brick, but leaves distant bricks alone', () => {
  const other = { x: 100, y: 220 };
  assert.deepEqual(snap({ x: 110, y: 180 }, [other]), { x: 100, y: 176 });
  assert.deepEqual(snap({ x: 95, y: 260 }, [other]), { x: 100, y: 264 });
  assert.deepEqual(snap({ x: 10, y: 100 }, [other]), { x: 10, y: 100 });
});

test('does not snap into an occupied slot or outside the canvas', () => {
  assert.deepEqual(snap({ x: 105, y: 180 }, [{ x: 100, y: 220 }, { x: 100, y: 176 }]), { x: 105, y: 180 });
  assert.deepEqual(snap({ x: 100, y: 60 }, [{ x: 100, y: 80 }]), { x: 100, y: 60 });
});

test('keeps the full brick inside the canvas', () => {
  assert.deepEqual(constrain({ x: -100, y: -100 }), { x: 8, y: 56.1 });
  assert.deepEqual(constrain({ x: 900, y: 900 }), { x: 243, y: 368 });
});

test('uses the full figure width for dragging and snapping, including after resizing', () => {
  const wide = canvasBounds(560, 420);
  assert.deepEqual(constrain({ x: -1000, y: 220 }, wide), { x: -62, y: 220 });
  assert.deepEqual(constrain({ x: 1000, y: 220 }, wide), { x: 313, y: 220 });
  assert.deepEqual(snap({ x: 300, y: 180 }, [{ x: 300, y: 220 }], wide), { x: 300, y: 176 });
  assert.deepEqual(constrain({ x: 313, y: 220 }, canvasBounds(320, 320)), { x: 243, y: 220 });
});

test('snaps one stud apart for half-width stacking in either direction', () => {
  const other = { x: 100, y: 220 };
  assert.deepEqual(snap({ x: 160, y: 180 }, [other]), { x: 165, y: 176 });
  assert.deepEqual(snap({ x: 40, y: 260 }, [other]), { x: 35, y: 264 });
});

test('live snapping releases when the pointer leaves the magnetic radius', () => {
  const others = [{ x: 100, y: 220 }];
  assert.deepEqual(snap({ x: 105, y: 180 }, others), { x: 100, y: 176 });
  assert.deepEqual(snap({ x: 100, y: 130 }, others), { x: 100, y: 130 });
});

test('rejects half-width snaps that overlap a brick already on that level', () => {
  const base = { x: 100, y: 220 };
  for (const x of [35, 165]) {
    const position = { x, y: 180 };
    assert.deepEqual(snap(position, [base, { x: 100, y: 176 }]), position);
  }
  const position = { x: 100, y: 180 };
  assert.deepEqual(snap(position, [base, { x: 165, y: 176 }]), position);
});

test('carries all connected bricks above the selected brick, including branches', () => {
  const base = { x: 100, y: 300 };
  const left = { x: 35, y: 256 };
  const right = { x: 165, y: 256 };
  const top = { x: 100, y: 212 };
  const loose = { x: 100, y: 100 };
  const bricks = [top, left, loose, right, base];
  const stack = stackAbove(base, bricks);
  assert.deepEqual(new Set(stack), new Set([base, left, right, top]));
  assert.deepEqual(stackAbove(top, bricks), [top]);
  moveStack(stack, { x: 110, y: 280 });
  assert.deepEqual([base, left, right, top, loose], [
    { x: 110, y: 280 }, { x: 45, y: 236 }, { x: 175, y: 236 },
    { x: 110, y: 192 }, { x: 100, y: 100 },
  ]);
});

test('keeps the whole stack inside the canvas without changing its connections', () => {
  const stack = [{ x: 100, y: 300 }, { x: 165, y: 256 }, { x: 100, y: 212 }];
  const offsets = stackOffsets(stack);
  moveStack(stack, { x: 900, y: -900 });
  assert.equal(stack[1].x, 243);
  assert.ok(Math.abs(stack[2].y - 56.1) < 0.001);
  assert.deepEqual(stackOffsets(stack), offsets);
});

test('rejects a group snap when an upper brick would overlap another brick', () => {
  const position = { x: 100, y: 264 };
  const others = [{ x: 100, y: 308 }, { x: 165, y: 220 }];
  const offsets = [{ x: 0, y: 0 }, { x: 0, y: -44 }];
  assert.equal(snap(position, others, canvasBounds(), offsets), position);
});

test('draws the right brick over its left neighbour regardless of creation order', () => {
  const base = { x: 100, y: 220 };
  const left = { x: 35, y: 176 };
  const right = { x: 165, y: 176 + Number.EPSILON * 176 };
  for (const bricks of [[right, base, left], [left, right, base], [base, left, right]]) {
    assert.deepEqual(bricks.sort(compareDepth), [base, left, right]);
  }
});
