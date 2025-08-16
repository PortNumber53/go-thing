/// <reference types="node" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'fs'
import os from 'os'
import path from 'path'

// https://vitejs.dev/config/
const proxyPaths = ['/chat', '/webhook', '/signup', '/login', '/logout', '/me', '/csrf'] as const
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

const allowedHosts = getAllowedHostsFromINI() ?? [
  'gothing.stage.portnumber53.com',
  'gothing.dev.portnumber53.com',
]

export default defineConfig({
  plugins: [react()],
  server: {
    allowedHosts,
    port: 5174,
    proxy: proxyConfig,
  },
})
