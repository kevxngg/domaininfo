import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The server applies a strict CSP (script-src 'self', no inline code), so the build must not
// inline scripts or styles: no module-preload polyfill, assets always emitted as files.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
    target: "es2022",
  },
  server: { host: "127.0.0.1" },
});
