import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

// A real Go static server/CSP, with isolated state and no production credentials.
const directory = await mkdtemp(join(tmpdir(), 'kpctl-web-browser-'));
const config = join(directory, 'controller.json');
await writeFile(config, JSON.stringify({
  listen: '127.0.0.1:18543', data_dir: join(directory, 'data'),
  admin_tokens: { test: 'browser-test-admin-token' }, builder_token: 'browser-test-builder-token',
  agent_bundle_dir: join(directory, 'empty-agent'), builder_binary: join(directory, 'no-builder'),
  rings: [1, 2], auto_rollout: { enabled: false },
}), { mode: 0o600 });
const server = spawn('go', ['run', './cmd/kpctl-controller', '-config', config], {
  cwd: fileURLToPath(new URL('../../', import.meta.url)), stdio: 'inherit', detached: true,
  env: { ...process.env, CGO_ENABLED: '0' },
});
let stopping = false;
async function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  try { process.kill(-server.pid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  await rm(directory, { recursive: true, force: true });
  process.exit(code);
}
process.once('SIGTERM', () => void stop());
process.once('SIGINT', () => void stop());
server.once('error', error => { console.error(error.message); void stop(1); });
server.once('exit', code => void stop(code || 0));
