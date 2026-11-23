import { fileURLToPath } from "node:url";
import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import { demoApi } from "./dev/plugin.js";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig(({ command, mode }) => {
  const root = fileURLToPath(new URL("./", import.meta.url));
  const demo = command === "serve" && mode === "mock";
  const environment = loadEnv(mode, root, "KPCTL_");
  const proxyTarget = environment.KPCTL_DEV_URL;
  if (demo && proxyTarget)
    throw new Error(
      "가상 데이터 모드에는 KPCTL_DEV_URL을 함께 설정할 수 없습니다. 실제 API 개발은 dev:api를 사용하세요.",
    );
  return {
    plugins: [react(), ...(demo ? [demoApi()] : []), tailwindcss()],
    base: "/ui/",
    resolve: {
      alias: { "@": fileURLToPath(new URL("./", import.meta.url)) },
    },
    server: {
      host: "127.0.0.1",
      fs: { strict: true, allow: [root] },
      proxy:
        !demo && proxyTarget
          ? { "/api": { target: proxyTarget, secure: true } }
          : undefined,
    },
    build: {
      outDir: fileURLToPath(
        new URL("../internal/controller/web/", import.meta.url),
      ),
      emptyOutDir: true,
      cssCodeSplit: false,
      sourcemap: false,
      rolldownOptions: {
        output: {
          entryFileNames: "app.js",
          chunkFileNames: "chunk-[hash].js",
          assetFileNames: (asset) =>
            asset.names?.some((n) => n.endsWith(".css"))
              ? "style.css"
              : "[name]-[hash][extname]",
        },
      },
    },
    test: {
      environment: "jsdom",
      setupFiles: "./src/test/setup.js",
      include: ["src/**/*.test.{js,jsx}"],
      restoreMocks: true,
    },
  };
});
