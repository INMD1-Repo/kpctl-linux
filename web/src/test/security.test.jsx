import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import App from '../App.jsx';
import { TOKEN_KEY } from '../api.js';
import { response, settingsFixture, signingFixture, statusFixture, vmTestFixture } from './fixtures.js';

function mountSecurity({ status = statusFixture(), settings = settingsFixture(), route } = {}) {
  sessionStorage.setItem(TOKEN_KEY, 'security-admin');
  const calls = [];
  vi.stubGlobal('fetch', vi.fn(async (path, options = {}) => {
    const call = { path: String(path), method: options.method, body: options.body ? JSON.parse(options.body) : undefined };
    calls.push(call);
    const custom = route?.(call);
    if (custom !== undefined) return custom;
    if (call.path === '/api/status') return response(status);
    if (call.path === '/api/settings') return response(settings);
    if (call.path.endsWith('/patches')) return response([{ id: 'p1', state: 'active', source: 'ubuntu', title: '보안 수정', cves: ['CVE-2099-1234'] }]);
    return response({ message: '완료' });
  }));
  render(<App />);
  return { calls, mutations: () => calls.filter(call => call.method !== 'GET') };
}

async function showPage(name) {
  const navigation = await screen.findByRole('navigation', { name: '화면' });
  fireEvent.click(within(navigation).getByRole('button', { name, exact: true }));
}

describe('보안·서명과 VM 증거 화면', () => {
  it('키별 등록 상태·MOK 대기·제외 사유와 보안 경고를 호스트별로 표시한다', async () => {
    const status = statusFixture();
    const old = structuredClone(status.hosts[0]);
    old.id = 'old-host'; old.hostname = 'old-key-only';
    old.status.enrolled_certs = { 'prod-2026': 'not_enrolled', 'prod-2025': 'enrolled' };
    old.rollout_eligibility = { status: 'eligible', key_id: 'prod-2025' };
    const blocked = structuredClone(status.hosts[0]);
    blocked.id = 'blocked'; blocked.hostname = 'console-pending';
    blocked.status.enrolled_certs = { 'prod-2026': 'not_enrolled', 'prod-2025': 'not_enrolled' };
    blocked.status.mok_pending = true;
    blocked.status.security_warning = '<img src=x onerror=alert(1)> 상태 확인 필요';
    blocked.rollout_eligibility = { status: 'blocked_mok_missing', reason: '다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요' };
    status.hosts.push(old, blocked);
    const app = mountSecurity({ status });
    await showPage('호스트');
    expect(screen.getByText(/배포 제외 1대/)).toBeTruthy();
    const row = screen.getByText('console-pending').closest('tr');
    expect(within(row).getByText('서명 필요')).toBeTruthy();
    for (const name of ['Firmware', 'uefi', 'Secure Boot', 'on', 'Lockdown', 'integrity', 'sig_enforce', 'off']) expect(within(row).getByText(name)).toBeTruthy();
    expect(within(row).getAllByText('미등록')).toHaveLength(2);
    expect(within(row).getByText(/MOK 등록 예약됨/)).toBeTruthy();
    expect(within(row).getByText(/배포 제외: 다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요/)).toBeTruthy();
    expect(within(row).getByText(/<img src=x onerror=alert\(1\)>/)).toBeTruthy();
    expect(document.querySelector('img[src="x"], [onerror]')).toBeNull();
    const oldRow = screen.getByText('old-key-only').closest('tr');
    expect(within(oldRow).getByText('등록됨')).toBeTruthy();
    expect(within(oldRow).getByText(/배포 서명 키:/).textContent).toContain('prod-2025');
    expect(app.mutations()).toHaveLength(0);
  });

  it('보안 필드가 없는 이전 보고는 서명 필요와 등록 상태 미확인으로 표시한다', async () => {
    const status = statusFixture();
    for (const field of ['firmware', 'secure_boot', 'lockdown', 'sig_enforce', 'signature_required', 'security_warning', 'enrolled_certs']) delete status.hosts[0].status[field];
    delete status.hosts[0].rollout_eligibility;
    mountSecurity({ status });
    await showPage('호스트');
    const row = screen.getByText('canary').closest('tr');
    expect(within(row).getByText('서명 필요')).toBeTruthy();
    expect(within(row).getByText('인증서 등록 상태 미확인')).toBeTruthy();
    expect(within(row).getByText(/secure_boot, lockdown, sig_enforce 상태 미확인/)).toBeTruthy();
    expect(within(row).queryByText('서명 불필요')).toBeNull();
  });

  it('작업·패치·승인 검토에 모드·키·산출물 해시와 실패·생략 단계를 보여준다', async () => {
    const status = statusFixture();
    const result = vmTestFixture({ status: 'failed', sha256: 'a'.repeat(64), modes: ['sb_on', 'bios'], error: '이미지 설정 오류', steps: [
      { name: 'boot', status: 'failed', mode: 'sb_on', key_id: 'prod-2026', detail: 'Secure Boot 서명 강제가 꺼져 있습니다' },
      { name: 'smoke', status: 'skipped', mode: 'bios', key_id: 'prod-2025', detail: 'smoke_cmd 미설정' },
    ] });
    status.jobs[0].status = 'built';
    status.jobs[0].vm_test = result;
    status.jobs[0].signing_artifacts['prod-2026'].sha256 = result.sha256;
    status.jobs[0].signing_artifacts['prod-2026'].vm_test = result;
    mountSecurity({ status });
    await showPage('빌드 작업');
    const row = screen.getByRole('button', { name: '검토·승인' }).closest('tr');
    fireEvent.click(within(row).getByText('작업 2 VM 시험'));
    expect(within(row).getByText('부팅·서명 강제 확인')).toBeTruthy();
    expect(within(row).getByText('Smoke 명령')).toBeTruthy();
    expect(within(row).getByText('생략')).toBeTruthy();
    expect(within(row).getByText('sb_on · 키 prod-2026')).toBeTruthy();
    expect(within(row).getByText('bios · 키 prod-2025')).toBeTruthy();
    expect(within(row).getByText(/시험 산출물 SHA256:/).textContent).toContain(result.sha256);
    expect(within(row).getByText(/키 prod-2026 \(활성\)/).textContent).toContain(result.sha256);
    fireEvent.click(within(row).getByRole('button', { name: '검토·승인' }));
    expect(within(screen.getByRole('dialog')).getByText('이미지 설정 오류')).toBeTruthy();
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: '닫기' }));
    await showPage('패치');
    const patch = await screen.findByText('보안 수정');
    expect(within(patch.closest('tr')).getByText('작업 2 VM 시험')).toBeTruthy();
    expect(within(patch.closest('tr')).getByText('Secure Boot 서명 강제가 꺼져 있습니다')).toBeTruthy();
  });

  it('Settings는 공개 키·만료 경고만 표시하고 추가 비밀 필드는 렌더링하지 않는다', async () => {
    const signing = signingFixture({ keys: [{ id: 'prod-expiring', active: true, expires_at: '2026-12-01T00:00:00Z', enrolled_hosts: 4, warning: '인증서 만료가 30일 이내입니다', cert: '/etc/kpctl/keys/secret.der', sign_command: ['secret-private-command'], private_key: 'PRIVATE KEY CONTENT' }], warnings: ['old-node: 옛 키를 제거하면 배포 제외됩니다'] });
    const app = mountSecurity({ settings: settingsFixture({ signing }) });
    await showPage('설정');
    expect(await screen.findByText('prod-expiring')).toBeTruthy();
    expect(screen.getByText('4대')).toBeTruthy();
    expect(screen.getByText('인증서 만료가 30일 이내입니다')).toBeTruthy();
    expect(screen.getByText(/old-node: 옛 키를 제거하면 배포 제외됩니다/)).toBeTruthy();
    for (const secret of ['/etc/kpctl/keys', 'secret-private-command', 'PRIVATE KEY CONTENT']) expect(document.body.textContent).not.toContain(secret);
    expect(app.mutations()).toHaveLength(0);
  });

  it('서명 키 필드가 없는 이전 Settings 응답도 폼과 미확인 안내를 유지한다', async () => {
    mountSecurity({ settings: settingsFixture({ signing: undefined }) });
    await showPage('설정');
    expect(await screen.findByText('컨트롤러가 서명 키 정보를 보고하지 않았습니다.')).toBeTruthy();
    expect(screen.getByRole('button', { name: '저장', exact: true })).toBeTruthy();
  });

  it('웹 승급 결과의 제외 대수와 호스트별 사유를 성공 안내에 보존한다', async () => {
    const app = mountSecurity({ route: call => call.path.endsWith('/promote') ? response({ version: 2, excluded_count: 1, excluded_hosts: [{ id: 'h-mok', hostname: 'mok-node', reason: 'MOK 등록 필요' }] }) : undefined });
    await screen.findByRole('navigation', { name: '화면' });
    fireEvent.click(screen.getByRole('button', { name: '링 2 승급' }));
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: '승급', exact: true }));
    await waitFor(() => expect(screen.getByText(/배포 제외 1대 — mok-node: MOK 등록 필요/)).toBeTruthy());
    expect(app.mutations()).toHaveLength(1);
  });
});
