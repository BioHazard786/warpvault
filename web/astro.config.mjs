// @ts-check
import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";

// https://astro.build/config
export default defineConfig({
  build: {
    format: "file",
  },
  vite: {
    envDir: "../",
    envPrefix: ["PUBLIC_", "WARPVAULT_"],
    plugins: [tailwindcss()],
    server: {
      proxy: {
        "/api": "http://localhost:8080",
        "/v/": "http://localhost:8080",
        "/d/": "http://localhost:8080",
      },
    },
  },
});
