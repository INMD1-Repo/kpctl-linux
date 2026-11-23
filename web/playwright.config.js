import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests', workers: 1, retries: 0,
  use: { baseURL: 'http://127.0.0.1:18543', viewport: { width: 1440, height: 1000 }, trace: 'retain-on-failure' },
  webServer: { command: 'node scripts/test-server.mjs', url: 'http://127.0.0.1:18543/', timeout: 120000, reuseExistingServer: false, gracefulShutdown: { signal: 'SIGTERM', timeout: 5000 } },
});
