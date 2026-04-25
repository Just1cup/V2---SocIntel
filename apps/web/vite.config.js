import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const webHost = env.VITE_DEV_HOST || "127.0.0.1";
  const webPort = Number(env.VITE_DEV_PORT || 5173);
  const allowedHosts = (env.VITE_ALLOWED_HOSTS || "localhost,127.0.0.1")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const corsOriginPattern = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;
  const baseSecurityHeaders = {
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
  };
  const devSecurityHeaders = {
    ...baseSecurityHeaders,
  };
  const previewSecurityHeaders = {
    ...baseSecurityHeaders,
    "Content-Security-Policy":
      "default-src 'self'; connect-src 'self' http://localhost:8000 http://127.0.0.1:8000; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  };

  return {
    plugins: [react()],
    server: {
      host: webHost,
      port: webPort,
      strictPort: true,
      allowedHosts,
      cors: {
        origin: corsOriginPattern,
        credentials: true,
      },
      headers: devSecurityHeaders,
    },
    preview: {
      host: webHost,
      port: webPort,
      strictPort: true,
      allowedHosts,
      headers: previewSecurityHeaders,
    },
    build: {
      target: "es2022",
      cssCodeSplit: true,
      sourcemap: false,
      reportCompressedSize: true,
      chunkSizeWarningLimit: 2000,
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (id.includes("node_modules")) {
              if (id.includes("react")) return "react-vendor";
              return "vendor";
            }
            if (id.includes("mitre-enterprise-data")) {
              return "mitre-data";
            }
            if (id.includes("MitreView")) {
              return "mitre-view";
            }
            return undefined;
          },
        },
      },
    },
  };
});
