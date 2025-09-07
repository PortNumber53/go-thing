/// <reference types="node" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'fs'
import os from 'os'
import path from 'path'

// https://vitejs.dev/config/
const proxyPaths = ['/chat', '/webhook', '/signup', '/login', '/logout', '/me', '/csrf', '/api'] as const
const proxyConfig = proxyPaths.reduce<Record<string, { target: string; changeOrigin: boolean }>>((acc, path) => {
  acc[path] = {
    target: 'http://127.0.0.1:7866',
    changeOrigin: true,
  }
  return acc
}, {})

function getAllowedHostsFromINI(): string[] | null {
  try {
    const iniPath = path.join(os.homedir(), '.config', 'go-thing', 'config.ini')
    const raw = fs.readFileSync(iniPath, 'utf8')
    // Find the ALLOWED_ORIGINS line (first occurrence)
    const match = raw.match(/^\s*ALLOWED_ORIGINS\s*=\s*(.+)$/m)
    if (!match) return null
    const value = match[1].trim()
    // Remove surrounding quotes if present
    const unquoted = value.replace(/^"|"$/g, '')
    // Split by comma into origins
    const origins = unquoted
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
    // Convert origins to hostnames for Vite allowedHosts
    const hosts = origins
      .map((origin) => {
        try {
          const u = new URL(origin)
          return u.hostname
        } catch {
          // If it's already a hostname (no scheme), keep as-is
          return origin.replace(/^https?:\/\//, '').replace(/:.*$/, '')
        }
      })
      .filter(Boolean)
    return hosts.length ? Array.from(new Set(hosts)) : null
  } catch {
    return null
  }
}

const allowedHosts = Array.from(new Set([
  ...(getAllowedHostsFromINI() ?? [
    'gothing.stage.portnumber53.com',
    'gothing.dev.portnumber53.com',
    'zenbook.tail87917.ts.net',
  ]),
  'localhost',
  '127.0.0.1',
]))

export default defineConfig({
  plugins: [react()],
  server: {
    allowedHosts,
    port: 5174,
    proxy: proxyConfig,
    // Optional: enable polling for filesystems where native FS events are unreliable (NFS/WSL/Docker bind mounts)
    watch: (() => {
      const usePolling = process.env.VITE_WATCH_POLL === '1' || process.env.VITE_WATCH_POLL === 'true'
      if (!usePolling) return undefined
      const interval = process.env.VITE_WATCH_INTERVAL ? Number(process.env.VITE_WATCH_INTERVAL) : 200
      return { usePolling, interval }
    })(),
    // Ensure Vite HMR websocket connects to the public HTTPS domain when behind a proxy
    // Only enable this override when VITE_HMR_HOST is provided; otherwise, let Vite default for localhost.
    hmr: (() => {
      const envHost = process.env.VITE_HMR_HOST
      if (!envHost) return undefined
      const envProtocol = process.env.VITE_HMR_PROTOCOL
      const envClientPort = process.env.VITE_HMR_CLIENT_PORT
      const host = envHost
      const protocol = (envProtocol || 'wss') as 'ws' | 'wss'
      const clientPort = envClientPort ? Number(envClientPort) : 443
      const path = '/vite-hmr'
      return { protocol, host, clientPort, path }
    })(),
    // Helps Vite construct absolute URLs in proxy scenarios; only set when overriding HMR
    origin: (() => {
      const envHost = process.env.VITE_HMR_HOST
      return envHost ? `https://${envHost}` : undefined
    })(),
  },
})
