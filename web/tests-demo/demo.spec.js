import { test, expect } from '@playwright/test';

test.beforeEach(async ({ request }) => {
  const response = await request.post('/api/dev/reset', { headers: { Authorization: 'Bearer demo-admin-token' }, data: { scenario: 'mixed' } });
  expect(response.ok()).toBe(true);
});

test('개발 서버 하나로 데이터 조회·diff·가상 승인·설정·오류·초기화를 시험한다', async ({ page }) => {
  const errors = [], external = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => { if (new URL(request.url()).host !== '127.0.0.1:18544') external.push(request.url()); });
  await page.goto('/ui/');
  await expect(page.getByLabel('개발 환경')).toContainText('개발 환경 · 가상 데이터');
  await expect(page.getByRole('navigation')).toBeVisible();
  await expect(page.getByText('demo-builder24', { exact: true })).toBeVisible();
  await page.getByRole('navigation').getByRole('button', { name: /^빌드 작업/ }).click();
  // 정식 작업과 출시 전 작업이 함께 있으므로 승인할 정식 작업 번호를 고정합니다.
  const officialJob = page.getByRole('row').filter({ has: page.getByRole('cell', { name: '6', exact: true }) });
  await officialJob.getByRole('button', { name: '검토·승인', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('가상 보안 수정 3');
  await page.getByRole('dialog').getByRole('button', { name: '승인 — 링 1 에 배포', exact: true }).click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  await page.getByRole('navigation').getByRole('button', { name: '패치', exact: true }).click();
  const officialPatch = page.getByRole('row').filter({ has: page.getByRole('cell', { name: '가상 보안 수정 3 — UI 개발용', exact: true }) });
  await officialPatch.getByRole('button', { name: 'diff', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('checked_example_3');
  await page.getByRole('button', { name: '닫기', exact: true }).click();
  await page.getByRole('navigation').getByRole('button', { name: 'CVE 현황', exact: true }).click();
  await page.getByRole('combobox', { name: 'CVE 상태' }).click();
  await page.getByRole('option', { name: '모든 기록', exact: true }).click();
  await expect(page.getByRole('link', { name: 'CVE-2099-1000', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '다음', exact: true }).click();
  await expect(page.getByRole('link', { name: 'CVE-2099-1015', exact: true })).toBeVisible();
  await page.getByRole('navigation').getByRole('button', { name: '설정', exact: true }).click();
  await page.getByLabel('자동 승급 전 관찰', { exact: true }).fill('1500');
  await page.getByRole('button', { name: '저장', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('설정을 저장했습니다.');
  await page.getByLabel('시나리오', { exact: false }).selectOption('source-error');
  await page.getByRole('button', { name: '가상 데이터 초기화', exact: true }).click();
  await expect(page.getByRole('navigation')).toBeVisible();
  await expect(page.getByLabel('시나리오', { exact: false })).toHaveValue('source-error');
  await page.getByRole('navigation').getByRole('button', { name: 'CVE 현황', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('공식 목록 조회 실패');
  await page.getByLabel('시나리오', { exact: false }).selectOption('empty');
  await page.getByRole('button', { name: '가상 데이터 초기화', exact: true }).click();
  await expect(page.getByText('아직 배포 기록이 없습니다.', { exact: false })).toBeVisible();
  expect(errors).toEqual([]); expect(external).toEqual([]);
});
