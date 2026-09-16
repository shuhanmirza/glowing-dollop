// Minimal self-contained confetti burst for the "identity added" success cue.
//
// Pure canvas, no dependencies and no remote code (Manifest V3 forbids remote
// script). Appends a full-viewport, click-through canvas, animates particles
// for a couple of seconds, then removes itself.

export function burst(durationMs = 2600) {
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
  const cx = window.innerWidth / 2
  const cy = window.innerHeight / 3
  const parts = []
  for (let i = 0; i < 160; i++) {
    const angle = Math.random() * Math.PI * 2
    const speed = 4 + Math.random() * 9
    parts.push({
      x: cx + (Math.random() - 0.5) * 100,
      y: cy,
      vx: Math.cos(angle) * speed,
      vy: Math.sin(angle) * speed - 4,
      g: 0.22 + Math.random() * 0.12,
      size: 6 + Math.random() * 7,
      color: colors[i % colors.length],
      rot: Math.random() * Math.PI,
      vr: (Math.random() - 0.5) * 0.35,
      shape: Math.random() < 0.5 ? 'rect' : 'circle',
    })
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
