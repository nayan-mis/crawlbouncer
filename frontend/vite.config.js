import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Built assets are served under /dashboard/ (see backend/app/main.py's
// dashboard-serving routes) — the marketing site owns "/" and its own
// top-level paths, so the React app's client-side routes (/domains,
// /settings, etc.) live under this base to avoid colliding with them.
export default defineConfig({
  base: '/dashboard/',
  plugins: [react()],
  build: {
    outDir: 'dist',
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test-setup.js',
  },
})
