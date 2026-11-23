import { test, expect } from '@playwright/test';
import { builderFixture, coverageFixture, settingsFixture, statusFixture } from '../src/test/fixtures.js';

async function prepare(page, { status = statusFixture(), route } = {}) {
  const mutations = [];
  const errors = [];
  const external = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  page.on('request', request => { if (new URL(request.url()).origin !== 'http://127.0.0.1:18543') external.push(request.url()); });
  await page.route('**/api/**', async intercepted => {
    const request = intercepted.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();
    if (method !== 'GET') mutations.push({ path, body: request.postDataJSON() });
    if (route && await route(intercepted, path, method)) return;
    if (path === '/api/status') return intercepted.fulfill({ json: status });
    if (path === '/api/settings') return intercepted.fulfill({ json: settingsFixture() });
    if (path === '/api/coverage') return intercepted.fulfill({ json: coverageFixture({ source_stale: true }) });
    if (path.endsWith('/patches')) return intercepted.fulfill({ json: [{ id: 'p1', state: 'active', title: '검토할 수정', cves: ['CVE-2026-43083'], source: 'ubuntu' }] });
    if (path.endsWith('/diff')) return intercepted.fulfill({ contentType: 'text/plain', body: '+safe\n-unsafe' });
    if (path === '/api/audit') return intercepted.fulfill({ contentType: 'text/plain', body: 'first\nsecond' });
    return intercepted.fulfill({ status: 501, json: { error: '시험에 정의하지 않은 요청' } });
  });
  const response = await page.goto('/');
  expect(response.headers()['content-security-policy']).toContain("script-src 'self'");
  expect(response.headers()['content-security-policy']).not.toContain('unsafe-inline');
  await page.getByLabel('관리자 토큰').fill('browser-test-admin-token');
  await page.getByRole('button', { name: '로그인', exact: true }).click();
  await expect(page.getByRole('navigation')).toBeVisible();
  return { mutations, errors, external };
}
async function tab(page, name) {
  if (!await page.getByRole('navigation').isVisible()) await page.getByRole('button', { name: 'Toggle Sidebar', exact: true }).click();
  await page.getByRole('navigation').getByRole('button', { name, exact: true }).click();
}

test('CVE 시험의 상태·실시간 로그와 모바일 표시', async ({ page }) => {
  const builder = builderFixture();
  builder.cache = { enabled: true, kernel: '6.8.0-136-generic', hits: 40, misses: 60, hit_rate: 0.4, build_seconds: 80,
    warning: 'ccache 적중률 40.0% (70% 미만). 기준 캐시를 확인하세요.' };
  let reads = 0;
  const result = await prepare(page, { status: statusFixture({ jobs: [], builders: { builder24: builder } }), route: async (intercepted, path) => {
    if (path !== '/api/builders/builder24') return false;
    await intercepted.fulfill({ json: { builder, log: `실행 ${++reads}\n<img src=x onerror=alert(1)>\ncompiler output` } });
    return true;
  } });
  await tab(page, '빌드 작업');
  await expect(page.getByText('CVE-2099-1004 · abcdef012345')).toBeVisible();
  await expect(page.getByText('83.0 GiB / 150.0 GiB')).toBeVisible();
  await expect(page.getByText(/40.0% 적중/)).toBeVisible();
  await expect(page.getByText(/70% 미만/)).toBeVisible();
  await page.getByRole('button', { name: '실시간 상태·로그', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.locator('pre')).toContainText('실행 1');
  await expect(dialog.locator('pre')).toContainText('실행 2', { timeout: 10000 });
  await expect(page.locator('img[src="x"], [onerror]')).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(result.errors).toEqual([]); expect(result.external).toEqual([]); expect(result.mutations).toEqual([]);
});

test('이전 목표가 있어도 최신 누적 버전으로 바로 적용', async ({ page }) => {
  const status = statusFixture({ latest_released: { '6.8.0-136-generic': 7 } });
  status.hosts[0].ring = 2; status.hosts[0].status.version = 1;
  status.hosts[0].update_now_kernel = '6.8.0-136-generic'; status.hosts[0].update_now_version = 2;
  const result = await prepare(page, { status, route: async (intercepted, path, method) => {
    if (path !== '/api/hosts/host-1/update-now' || method !== 'POST') return false;
    await intercepted.fulfill({ json: { version: 7, message: '최신 누적본 적용 요청' } });
    return true;
  } });
  await tab(page, '호스트');
  await expect(page.getByRole('button', { name: '즉시 업데이트 취소', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '최신 누적 v7 적용', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toContainText('v1 → 최신 누적 v7');
  await expect(dialog).toContainText('중간 버전을 설치하지 않고');
  expect(result.mutations).toEqual([]);
  await dialog.getByRole('button', { name: 'v7 적용', exact: true }).click();
  await expect(dialog).not.toBeVisible();
  expect(result.mutations).toEqual([{ path: '/api/hosts/host-1/update-now', body: { kernel: '6.8.0-136-generic', version: 7 } }]);
  expect(result.errors).toEqual([]); expect(result.external).toEqual([]);
});

test('Go 내장 React의 7개 화면·CSP·안전한 출력', async ({ page }) => {
  const result = await prepare(page);
  await expect(page.getByRole('heading', { name: '처리할 일' })).toBeVisible();
  await tab(page, '빌드 작업'); await expect(page.getByRole('heading', { name: '최근 작업 30개' })).toBeVisible();
  await tab(page, '호스트'); await expect(page.getByText('canary', { exact: true })).toBeVisible();
  await tab(page, '패치'); await expect(page.getByText('검토할 수정', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'diff', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('+safe');
  await page.getByRole('button', { name: '닫기', exact: true }).click();
  await tab(page, 'CVE 현황');
  await expect(page.getByText('<img src=x onerror=alert(1)>', { exact: true })).toBeVisible();
  await expect(page.locator('img[src="x"], [onerror]')).toHaveCount(0);
  await expect(page.locator('[data-sidebar="sidebar"]').getByText('kpctl-linux', { exact: true })).toBeVisible();
  await expect(page).toHaveTitle('kpctl-linux 관리자');
  await expect(page.getByText('공식 정보 부족 99', { exact: true })).toBeVisible();
  await tab(page, '설정');
  await page.getByLabel('자동 승급 전 관찰', { exact: true }).fill('1500');
  await expect(page.getByLabel('자동 승급 전 관찰', { exact: true })).toHaveValue('1500');
  await tab(page, '감사 로그'); await expect(page.locator('pre')).toContainText('second\nfirst');
  await page.setViewportSize({ width: 390, height: 844 });
  await tab(page, '호스트');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  expect(result.errors).toEqual([]); expect(result.external).toEqual([]); expect(result.mutations).toEqual([]);
});

test('재부팅 대상 확인·처리 중 중복 클릭·Esc 차단', async ({ page }) => {
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const result = await prepare(page, { route: async (intercepted, path) => {
    if (!path.endsWith('/reboot')) return false;
    await pending;
    await intercepted.fulfill({ json: { message: '테스트 승인' } });
    return true;
  } });
  await tab(page, '호스트');
  await page.getByRole('button', { name: '커널 점프 → 6.8.0-147-generic', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toContainText('6.8.0-136-generic → 6.8.0-147-generic');
  expect(result.mutations).toHaveLength(0);
  const button = dialog.getByRole('button', { name: '이 커널로 재부팅 승인', exact: true });
  await button.click();
  await expect(dialog.getByRole('button', { name: '처리 중…', exact: true })).toBeDisabled();
  await page.keyboard.press('Escape'); await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('button', { name: '닫기', exact: true })).toBeDisabled();
  expect(result.mutations).toEqual([{ path: '/api/hosts/host-1/reboot', body: { target_id: 'prepared-target-hash' } }]);
  release(); await expect(dialog).not.toBeVisible();
  expect(result.errors).toEqual([]);
});
