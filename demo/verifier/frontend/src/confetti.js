// Minimal self-contained confetti burst for the sign-in success celebration.
// Pure canvas, no dependencies and no network — appends a full-viewport,
// click-through canvas, animates particles, then removes itself.

export function burst(durationMs = 3000) {
  const canvas = document.createElement('canvas')
  canvas.style.cssText =
    'position:fixed;inset:0;width:100%;height:100%;pointer-events:none;z-index:9999'
  document.body.appendChild(canvas)

  const ctx = canvas.getContext('2d')
  const dpr = window.devicePixelRatio || 1
  function resize() {
    canvas.width = window.innerWidth * dpr
    canvas.height = window.innerHeight * dpr
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  }
  resize()
  window.addEventListener('resize', resize)

  const colors = ['#1a73e8', '#34a853', '#fbbc04', '#ea4335', '#a142f4', '#24c1e0']
  const parts = []
  // Two side cannons firing inward for a celebratory feel.
  for (const side of [0, 1]) {
    const originX = side === 0 ? 0 : window.innerWidth
    const dir = side === 0 ? 1 : -1
    for (let i = 0; i < 90; i++) {
      const speed = 6 + Math.random() * 11
      const angle = (-Math.PI / 4) + (Math.random() - 0.5) * 0.7
      parts.push({
        x: originX,
        y: window.innerHeight * 0.62,
        vx: Math.cos(angle) * speed * dir,
        vy: Math.sin(angle) * speed,
        g: 0.24 + Math.random() * 0.12,
        size: 6 + Math.random() * 7,
        color: colors[i % colors.length],
        rot: Math.random() * Math.PI,
        vr: (Math.random() - 0.5) * 0.4,
        shape: Math.random() < 0.5 ? 'rect' : 'circle',
      })
    }
  }

  const start = performance.now()
  function frame(now) {
    const t = now - start
    ctx.clearRect(0, 0, canvas.width, canvas.height)
    for (const p of parts) {
      p.vy += p.g
      p.x += p.vx
      p.y += p.vy
      p.rot += p.vr
      ctx.save()
      ctx.translate(p.x, p.y)
      ctx.rotate(p.rot)
      ctx.globalAlpha = Math.max(0, 1 - t / durationMs)
      ctx.fillStyle = p.color
      if (p.shape === 'rect') {
        ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size * 0.5)
      } else {
        ctx.beginPath()
        ctx.arc(0, 0, p.size / 2, 0, Math.PI * 2)
        ctx.fill()
      }
      ctx.restore()
    }
    if (t < durationMs) {
      requestAnimationFrame(frame)
    } else {
      window.removeEventListener('resize', resize)
      canvas.remove()
    }
  }
  requestAnimationFrame(frame)
}
