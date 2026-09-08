import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  // Relative asset URLs so the build works both at "/" and under "/vigia".
  base: "",
  plugins: [react(), tailwindcss()],
  server: {
    proxy: { "/api": "http://localhost:8110" },
  },
});
