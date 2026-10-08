import { defineConfig } from 'vite';
import { frontendSbom } from './scripts/frontend-sbom.mjs';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte(), frontendSbom()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
});
