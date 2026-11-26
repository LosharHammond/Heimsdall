import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: "src/web",
  plugins: [react()],
  build: { outDir: "../../dist/web", emptyOutDir: true, sourcemap: false },
  server: {
    port: 5173,
    // Only real API paths. A bare "/api" prefix would also catch the dashboard's own module /api.ts (src/web/api.ts)
    // and send it to the API server, which leaves the page blank.
    proxy: { "^/api/": "http://localhost:8787", "^/v1/": "http://localhost:8787" },
  },
});
