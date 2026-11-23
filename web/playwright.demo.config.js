import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests-demo', workers: 1, retries: 0,
  use: { baseURL: 'http://127.0.0.1:18544', viewport: { width: 1440, height: 1000 }, trace: 'retain-on-failure' },
  webServer: { command: 'npm run dev:mock -- --port 18544 --strictPort', url: 'http://127.0.0.1:18544/ui/', timeout: 30000, reuseExistingServer: false, gracefulShutdown: { signal: 'SIGTERM', timeout: 5000 } },
});
