(() => {
  function canvasBounds(width = 420, height = 420) {
    const margin = (width * 420 / height - 420) / 2;
    return { minX: 8 - margin, maxX: 243 + margin, minY: 56.1, maxY: 368 };
  }
  const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
  const constrain = ({ x, y }, bounds = canvasBounds()) => ({
    x: clamp(x, bounds.minX, bounds.maxX),
    y: clamp(y, bounds.minY, bounds.maxY),
  });

  const overlaps = (a, b) => Math.abs(a.x - b.x) < 130 - 0.01 && Math.abs(a.y - b.y) < 44 - 0.01;
  const compareDepth = (a, b) => Math.abs(a.y - b.y) < 0.01 ? a.x - b.x : b.y - a.y;

  function stackAbove(brick, bricks) {
    const stack = [brick];
    for (const lower of stack) {
      for (const upper of bricks) {
        const dx = Math.abs(upper.x - lower.x);
        if (!stack.includes(upper) && Math.abs(lower.y - upper.y - 44) < 0.01
          && (dx < 0.01 || Math.abs(dx - 65) < 0.01)) stack.push(upper);
      }
    }
    return stack;
  }

  function stackOffsets(stack) {
    return stack.map(brick => ({ x: brick.x - stack[0].x, y: brick.y - stack[0].y }));
  }

  function movementBounds(offsets, bounds) {
    return {
      minX: bounds.minX - Math.min(...offsets.map(offset => offset.x)),
      maxX: bounds.maxX - Math.max(...offsets.map(offset => offset.x)),
      minY: bounds.minY - Math.min(...offsets.map(offset => offset.y)),
      maxY: bounds.maxY - Math.max(...offsets.map(offset => offset.y)),
    };
  }

  function moveStack(stack, position, bounds = canvasBounds()) {
    const offsets = stackOffsets(stack);
    const target = constrain(position, movementBounds(offsets, bounds));
    stack.forEach((brick, index) => Object.assign(brick, {
      x: target.x + offsets[index].x, y: target.y + offsets[index].y,
    }));
  }

  function snap(position, others, bounds = canvasBounds(), offsets = [{ x: 0, y: 0 }]) {
    let closest = 30;
    let result = position;
    const limits = movementBounds(offsets, bounds);
    for (const offset of offsets) {
      for (const other of others) {
        for (const [x, y] of [[0, -44], [-65, -44], [65, -44], [0, 44], [-65, 44], [65, 44]]) {
          const candidate = { x: other.x + x - offset.x, y: other.y + y - offset.y };
          const limited = constrain(candidate, limits);
          if (limited.x !== candidate.x || limited.y !== candidate.y) continue;
          if (offsets.some(part => others.some(brick => overlaps(brick, {
            x: candidate.x + part.x, y: candidate.y + part.y,
          })))) continue;
          const distance = Math.hypot(position.x - candidate.x, position.y - candidate.y);
          if (distance < closest) {
            closest = distance;
            result = candidate;
          }
        }
      }
    }
    return result;
  }

  if (typeof module !== 'undefined') module.exports = { canvasBounds, constrain, snap, stackAbove, moveStack, stackOffsets, compareDepth };
  if (typeof document === 'undefined') return;

  let resizeObserver;
  function init() {
    const svg = document.querySelector('.auth-assembly');
    if (svg?.dataset.interactive) return;
    resizeObserver?.disconnect();
    if (!svg) return;
    svg.dataset.interactive = 'true';
    const bricks = [...svg.querySelectorAll('[data-brick]')].map(element => ({
      element, x: Number(element.dataset.x), y: Number(element.dataset.y),
    }));
    const status = document.getElementById('brick-status');
    let drag = null;
    let bounds = canvasBounds();

    function render() {
      for (const brick of [...bricks].sort(compareDepth)) {
        brick.element.setAttribute('transform', `translate(${brick.x} ${brick.y})`);
        svg.append(brick.element);
      }
    }
    function settle(brick, stack = stackAbove(brick, bricks)) {
      const position = snap(brick, bricks.filter(other => !stack.includes(other)), bounds, stackOffsets(stack));
      const connected = position !== brick;
      moveStack(stack, position, bounds);
      render();
      status.textContent = `${brick.element.dataset.brick} ${connected ? 'connected' : 'moved'}.`;
    }
    function point(event) {
      return new DOMPoint(event.clientX, event.clientY).matrixTransform(svg.getScreenCTM().inverse());
    }
    function finish(cancel = false) {
      if (!drag) return;
      const current = drag;
      drag = null;
      for (const brick of current.stack) brick.element.classList.remove('is-dragging');
      const others = bricks.filter(brick => !current.stack.includes(brick));
      if (current.stack.some(brick => others.some(other => overlaps(brick, other)))) cancel = true;
      if (cancel) {
        current.stack.forEach((brick, index) => Object.assign(brick, current.start[index]));
        render();
        status.textContent = 'Move cancelled.';
      } else {
        settle(current.brick, current.stack);
      }
      current.brick.element.focus({ preventScroll: true });
      if (svg.hasPointerCapture(current.pointerId)) svg.releasePointerCapture(current.pointerId);
    }
    svg.parentElement.addEventListener('contextmenu', event => {
      event.preventDefault();
      if (drag) return;
      const element = bricks[0].element.cloneNode(true);
      element.querySelectorAll('text').forEach(text => text.remove());
      element.classList.remove('is-dragging');
      element.classList.add('brick-grey');
      element.dataset.brick = 'Grey brick';
      element.setAttribute('aria-label', 'Move grey brick');
      const cursor = point(event);
      const brick = { element, ...constrain({ x: cursor.x - 65, y: cursor.y - 22 }, bounds) };
      bricks.push(brick);
      render();
      element.focus({ preventScroll: true });
      status.textContent = 'Grey brick added.';
    });
    svg.addEventListener('pointerdown', event => {
      if (event.button !== 0 || drag) return;
      const brick = bricks.find(item => item.element === event.target.closest('[data-brick]'));
      if (!brick) return;
      event.preventDefault();
      brick.element.focus({ preventScroll: true });
      const stack = stackAbove(brick, bricks);
      drag = { brick, stack, pointerId: event.pointerId, origin: point(event), start: stack.map(({ x, y }) => ({ x, y })) };
      for (const item of stack) item.element.classList.add('is-dragging');
      svg.setPointerCapture(event.pointerId);
    });
    svg.addEventListener('pointermove', event => {
      if (!drag || event.pointerId !== drag.pointerId) return;
      const current = point(event);
      const offsets = stackOffsets(drag.stack);
      const position = constrain({
        x: drag.start[0].x + current.x - drag.origin.x,
        y: drag.start[0].y + current.y - drag.origin.y,
      }, movementBounds(offsets, bounds));
      moveStack(drag.stack, snap(position, bricks.filter(other => !drag.stack.includes(other)), bounds, offsets), bounds);
      render();
    });
    svg.addEventListener('pointerup', event => {
      if (event.pointerId === drag?.pointerId) finish();
    });
    svg.addEventListener('pointercancel', () => finish(true));
    svg.addEventListener('lostpointercapture', () => finish(true));
    svg.addEventListener('keydown', event => {
      if (event.key === 'Escape') { finish(true); return; }
      const brick = bricks.find(item => item.element === event.target);
      if (!brick || drag) return;
      const moves = { ArrowLeft: [-10, 0], ArrowRight: [10, 0], ArrowUp: [0, -10], ArrowDown: [0, 10] };
      if (moves[event.key]) {
        event.preventDefault();
        const [x, y] = moves[event.key];
        moveStack(stackAbove(brick, bricks), { x: brick.x + x, y: brick.y + y }, bounds);
        render();
        brick.element.focus({ preventScroll: true });
      } else if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        settle(brick);
        brick.element.focus({ preventScroll: true });
      }
    });
    resizeObserver = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      if (!width || !height) return;
      finish(true);
      bounds = canvasBounds(width, height);
      for (const brick of bricks) Object.assign(brick, constrain(brick, bounds));
      render();
    });
    resizeObserver.observe(svg);
  }
  if (typeof document$ !== 'undefined') document$.subscribe(init);
  else if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
