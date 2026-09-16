import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// During local development (npm run dev / npm run preview) we relay /api to the
// Go backend so the browser talks to a single origin, mirroring what nginx does
// in the docker-compose setup. The backend host can be overridden with the
// BACKEND_URL env var (used by nothing yet, handy for native runs).
const backend = process.env.BACKEND_URL || 'http://localhost:11110'

// `proxy` is Vite's own dev-server config key (server.proxy); it must keep that
// name even though, in our domain language, it is "the blind relay" that carries
// API traffic. Renaming this key would silently disable /api forwarding.
const proxy = {
  '/api': {
    target: backend,
    changeOrigin: true,
  },
}

export default defineConfig({
  plugins: [vue()],
  server: { host: true, port: 5173, proxy },
  preview: { host: true, port: 5173, proxy },
})
