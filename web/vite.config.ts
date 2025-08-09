import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    allowedHosts: ['gothing.stage.portnumber53.com'],
    port: 5174,
    proxy: {
      '/chat': {
        target: 'http://127.0.0.1:7866',
        changeOrigin: true,
      },
      '/webhook': {
        target: 'http://127.0.0.1:7866',
        changeOrigin: true,
      },
    },
  },
})
