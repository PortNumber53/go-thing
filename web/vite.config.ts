import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
const proxyPaths = ['/chat', '/webhook', '/signup', '/login', '/logout', '/me'] as const
const proxyConfig = proxyPaths.reduce<Record<string, { target: string; changeOrigin: boolean }>>((acc, path) => {
  acc[path] = {
    target: 'http://127.0.0.1:7866',
    changeOrigin: true,
  }
  return acc
}, {})

export default defineConfig({
  plugins: [react()],
  server: {
    allowedHosts: ['gothing.stage.portnumber53.com'],
    port: 5174,
    proxy: proxyConfig,
  },
})
