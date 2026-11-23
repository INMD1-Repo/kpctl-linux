import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';

const root = fileURLToPath(new URL('../', import.meta.url));
const committed = fileURLToPath(new URL('../../internal/controller/web/', import.meta.url));
const output = await mkdtemp(join(tmpdir(), 'kpctl-web-build-'));
try {
  await build({ root, configFile: join(root, 'vite.config.js'), build: { outDir: output }, logLevel: 'warn' });
  const expected = (await readdir(output)).sort();
  const actual = (await readdir(committed)).sort();
  if (JSON.stringify(expected) !== JSON.stringify(actual)) throw new Error('내장 파일 목록이 다릅니다. make web을 실행하세요.');
  for (const file of expected) {
    const [fresh, saved] = await Promise.all([readFile(join(output, file)), readFile(join(committed, file))]);
    if (!fresh.equals(saved)) throw new Error(`${file}이 React 소스와 다릅니다. make web을 실행하세요.`);
  }
  const javascript = await readFile(join(output, 'app.js'), 'utf8');
  for (const marker of ['demo-admin-token', '/api/dev/', 'CVE-2099-']) {
    if (javascript.includes(marker)) throw new Error(`개발 데이터가 운영 번들에 포함됐습니다: ${marker}`);
  }
  console.log('React 소스와 Go 내장 번들이 일치합니다.');
} finally { await rm(output, { recursive: true, force: true }); }
