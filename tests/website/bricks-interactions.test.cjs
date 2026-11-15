const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function playground() {
  function brick(name, x, y) {
    const attributes = new Map();
    const classes = new Set();
    const element = {
      dataset: { brick: name, x: String(x), y: String(y) },
      classList: { add: value => classes.add(value), remove: value => classes.delete(value) },
      setAttribute: (name, value) => attributes.set(name, value),
      getAttribute: name => attributes.get(name),
      closest: () => element,
      cloneNode: () => brick(name, x, y),
      querySelectorAll: () => element.labels,
      labels: [{ remove: () => { element.labels = []; } }],
    };
    return element;
  }
  const factors = brick('Factors', 95, 358);
  const mfa = brick('MFA', 125, 228);
  const sessions = brick('Sessions', 155, 98);
  const elements = [factors, mfa, sessions];
  const captured = new Set();
  const status = { textContent: '' };
  let resize;
  const canvas = new EventTarget();
  const svg = Object.assign(new EventTarget(), {
    dataset: {}, parentElement: canvas,
    querySelectorAll: () => elements,
    append: element => {
      const index = elements.indexOf(element);
      if (index !== -1) elements.splice(index, 1);
      elements.push(element);
    },
    getScreenCTM: () => ({ inverse: () => ({}) }),
    setPointerCapture: id => captured.add(id),
    hasPointerCapture: id => captured.has(id),
    releasePointerCapture: id => captured.delete(id),
  });
  vm.runInNewContext(fs.readFileSync(require.resolve('../../docs/javascripts/bricks.js'), 'utf8'), {
    document: { readyState: 'complete', querySelector: () => svg, getElementById: () => status },
    DOMPoint: class {
      constructor(x, y) { this.x = x; this.y = y; }
      matrixTransform() { return this; }
    },
    ResizeObserver: class {
      constructor(callback) { resize = (width, height) => callback([{ contentRect: { width, height } }]); }
      observe() { resize(420, 420); }
    },
  });
  function emit(type, values = {}) {
    const event = new Event(type, { cancelable: true });
    for (const [key, value] of Object.entries({ button: 0, pointerId: 1, ...values })) {
      Object.defineProperty(event, key, { value });
    }
    (type === 'contextmenu' ? canvas : svg).dispatchEvent(event);
    return event;
  }
  const position = element => element.getAttribute('transform');
  return { emit, position, resize, factors, mfa, sessions, elements, status, captured };
}

test('pointer dragging snaps live, reports the drop, and carries a connected stack', () => {
  const game = playground();
  game.emit('pointerdown', { target: game.sessions, clientX: 155, clientY: 98 });
  assert.ok(game.captured.has(1));
  game.emit('pointermove', { clientX: 190, clientY: 184 });
  assert.equal(game.position(game.sessions), 'translate(190 184)');
  game.emit('pointerup');
  assert.equal(game.status.textContent, 'Sessions connected.');
  assert.equal(game.captured.size, 0);

  game.emit('pointerdown', { target: game.mfa, clientX: 125, clientY: 228 });
  game.emit('pointermove', { clientX: 145, clientY: 208 });
  game.emit('pointerup');
  assert.equal(game.position(game.mfa), 'translate(145 208)');
  assert.equal(game.position(game.sessions), 'translate(210 164)');
});

test('an overlapping pointer drop restores the original position', () => {
  const game = playground();
  game.emit('pointerdown', { target: game.sessions, clientX: 155, clientY: 98 });
  game.emit('pointermove', { clientX: 125, clientY: 228 });
  game.emit('pointerup');
  assert.equal(game.position(game.sessions), 'translate(155 98)');
  assert.equal(game.status.textContent, 'Move cancelled.');
  assert.equal(game.captured.size, 0);
});

test('pointer cancellation restores every brick in the dragged stack', () => {
  const game = playground();
  game.emit('pointerdown', { target: game.sessions, clientX: 155, clientY: 98 });
  game.emit('pointermove', { clientX: 190, clientY: 184 });
  game.emit('pointerup');
  game.emit('pointerdown', { target: game.mfa, clientX: 125, clientY: 228 });
  game.emit('pointermove', { clientX: 145, clientY: 208 });
  game.emit('pointercancel');
  assert.equal(game.position(game.mfa), 'translate(125 228)');
  assert.equal(game.position(game.sessions), 'translate(190 184)');
  assert.equal(game.captured.size, 0);
});

test('right-click spawns an unlabelled brick only where the constrained position is free', () => {
  const game = playground();
  const event = game.emit('contextmenu', { clientX: 220, clientY: 120 });
  assert.ok(event.defaultPrevented);
  assert.equal(game.elements.length, 3);
  assert.equal(game.status.textContent, 'No room for a brick here.');

  game.emit('contextmenu', { clientX: 0, clientY: 0 });
  assert.equal(game.elements.length, 4);
  const grey = game.elements.find(element => element.dataset.brick === 'Grey brick');
  assert.equal(game.position(grey), 'translate(8 56.1)');
  assert.equal(grey.labels.length, 0);
  assert.equal(game.status.textContent, 'Grey brick added.');
  game.emit('contextmenu', { clientX: -20, clientY: -20 });
  assert.equal(game.elements.length, 4);
  assert.equal(game.status.textContent, 'No room for a brick here.');
});

test('resizing preserves a connected assembly with two supporting bricks', () => {
  const game = playground();
  game.resize(800, 420);
  for (const [target, x, y, destinationX, destinationY] of [
    [game.mfa, 125, 228, 300, 228],
    [game.sessions, 155, 98, 365, 184],
    [game.factors, 95, 358, 430, 228],
  ]) {
    game.emit('pointerdown', { target, clientX: x, clientY: y });
    game.emit('pointermove', { clientX: destinationX, clientY: destinationY });
    game.emit('pointerup');
  }
  assert.equal(game.position(game.factors), 'translate(430 228)');
  assert.equal(game.position(game.sessions), 'translate(365 184)');
  game.resize(420, 420);
  assert.equal(game.position(game.mfa), 'translate(113 228)');
  assert.equal(game.position(game.sessions), 'translate(178 184)');
  assert.equal(game.position(game.factors), 'translate(243 228)');
});
