import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import App from '../App.jsx';
import { TOKEN_KEY } from '../api.js';
import { builderFixture, coverageFixture, response, settingsFixture, statusFixture } from './fixtures.js';

function mount({ status = statusFixture(), coverage = coverageFixture(), route } = {}) {
  sessionStorage.setItem(TOKEN_KEY, 'test-admin');
  const calls = [];
  const fetch = vi.fn(async (path, options = {}) => {
    const call = { path: String(path), method: options.method, body: options.body ? JSON.parse(options.body) : undefined, signal: options.signal };
    calls.push(call);
    const custom = route?.(call);
    if (custom !== undefined) return custom;
    if (call.path === '/api/status') return response(status);
    if (call.path === '/api/settings') return response(settingsFixture());
    if (call.path.startsWith('/api/coverage?')) return response(coverage);
    if (call.path.endsWith('/patches')) return response([{ id: 'p1', state: 'active', title: '검토할 수정', cves: ['CVE-2026-43083'], source: 'ubuntu' }]);
    if (call.path.endsWith('/diff')) return response('+safe\n-unsafe', 200, 'text/plain');
    if (call.path.endsWith('/log')) return response('build log <script>alert(1)</script>', 200, 'text/plain');
    if (call.path === '/api/audit') return response('first\nsecond', 200, 'text/plain');
    return response({ message: '완료' });
  });
  vi.stubGlobal('fetch', fetch);
  render(<App />);
  return { calls, fetch, status, coverage, mutations: () => calls.filter(call => call.method !== 'GET') };
}
async function ready() { await screen.findByRole('navigation', { name: '화면' }); }
async function page(name) { fireEvent.click(within(screen.getByRole('navigation')).getByRole('button', { name, exact: true })); }

describe('React 관리자 화면', () => {
  it.each([['debian', '12'], ['rocky', '10']])('%s %s 타이머의 정상 대기와 이전 빌더의 작업 조회를 구분한다', async (distro, release) => {
    const native = builderFixture({ name: distro, series: distro + release, up_to_date: false,
      kernels: [`native__${distro}__${release}__amd64__fixture`], environment: 'distribution',
      heartbeat_at: new Date(Date.now() - 70000).toISOString(), activity: { phase: 'idle' } });
    const old = { ...native, name: 'old', environment: '', activity: null, heartbeat_at: null };
    const outdated = { ...native, name: 'outdated', sha256: 'a'.repeat(64) };
    mount({ status: statusFixture({ builders: { [distro]: native, old, outdated } }) });
    await ready(); await page('빌드 작업');
    expect(screen.getAllByText('연결됨')).toHaveLength(2);
    expect(screen.getByText('작업 조회 확인')).toBeTruthy();
    expect(screen.getAllByText('설치 묶음으로 관리')).toHaveLength(2);
    expect(screen.getByText('모듈 검증 도구 갱신 필요')).toBeTruthy();
    expect(screen.queryByText('빌더 업데이트 대기')).toBeNull();
    expect(screen.queryByText('실시간 보고 미지원')).toBeNull();
  });
  it('수집 실패 유형을 표시하고 사유가 있어야 커밋별 관리자 제외를 전송한다', async () => {
    const kernel = '6.8.0-136-generic', commit = 'a'.repeat(40);
    const problem = { problem: 'objtool: unexpected klp reloc for new symbol', problem_kind: 'unsupported',
      problem_at: '2026-11-06T10:00:00Z', latest_tag: 'Ubuntu-6.8.0-147.147',
      problem_failure: { commit, cves: ['CVE-2026-72473'], input: { base_tag: 'Ubuntu-6.8.0-136.136', build_tool: 'klp' } } };
    const app = mount({ status: statusFixture({ upstream: { [kernel]: problem } }) });
    await ready();
    expect(screen.getByText(/도구가 지원하지 않는 변경/)).toBeTruthy();
    expect(screen.getByText(/확인된 정식 배포 태그/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '이 커밋 제외하고 수집 계속' }));
    const dialog = screen.getByRole('dialog');
    const submit = within(dialog).getByRole('button', { name: '제외하고 수집 계속' });
    expect(submit.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText('제외 사유 (필수)'), { target: { value: '  ' } });
    expect(submit.disabled).toBe(true);
    expect(app.mutations()).toHaveLength(0);
    fireEvent.change(within(dialog).getByLabelText('제외 사유 (필수)'), { target: { value: ' 별도 완화 후 커널 업데이트 ' } });
    fireEvent.click(submit);
    await waitFor(() => expect(app.mutations()).toHaveLength(1));
    expect(app.mutations()[0]).toMatchObject({ method: 'POST', path: `/api/kernels/${kernel}/commits/${commit}/exclude`,
      body: { reason: '별도 완화 후 커널 업데이트', problem_ref: problem.problem_at } });
  });

  it('관리자 제외는 미해결로 보이고 확인 후 취소할 수 있다', async () => {
    const kernel = '6.8.0-136-generic', commit = 'a'.repeat(40);
    const decision = { kernel, commit, cves: ['CVE-2026-43083'], title: '검토 중인 커밋', reason: '업데이트 대기',
      decision: { by: 'tester', at: new Date().toISOString(), input: { base_tag: 'Ubuntu-6.8.0-136.136', build_tool: 'klp', image: 'sha256:1234' } } };
    const app = mount({ status: statusFixture({ unpatchable: [decision] }), coverage: coverageFixture({ rows: [
      { cve: 'CVE-2026-43083', base_status: 'affected', status: 'admin_excluded', details: ['미해결 · 관리자 제외: 업데이트 대기'] },
    ] }) });
    await ready(); await page('CVE 현황');
    expect(await screen.findByText('미해결 · 관리자 제외')).toBeTruthy();
    await page('패치');
    expect(await screen.findByText('미해결 · 관리자 제외')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '제외 취소' }));
    expect(app.mutations()).toHaveLength(0);
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: '취소하고 재시험' }));
    await waitFor(() => expect(app.mutations()).toHaveLength(1));
    expect(app.mutations()[0]).toMatchObject({ method: 'DELETE', path: `/api/kernels/${kernel}/commits/${commit}/exclude` });
  });

  it('관리자 제외로 수집을 계속할 때 실제 원인 해결 문구를 붙이지 않는다', async () => {
    const status = statusFixture({ upstream: { '6.8.0-136-generic': { problem_resolution: 'admin_exclusion' } } });
    status.tracks[0].auto_hold = '수집 검토 필요';
    status.tracks[0].auto_hold_resolved = '관리자 제외로 수집 계속 · CVE 미해결';
    mount({ status }); await ready();
    expect(screen.getByText('관리자 제외 · 재개 대기')).toBeTruthy();
    expect(screen.getByText(/관리자 결정.*관리자 제외로 수집 계속/)).toBeTruthy();
    expect(screen.queryByText(/원인 해결됨/)).toBeNull();
  });

  it('작업이 없어도 CVE 시험 상태·자원을 표시하고 대화상자에서 로그를 갱신·중지한다', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    const builder = builderFixture();
    builder.resources.disk_minimum = 64 * 1073741824;
    builder.maintenance = '비활성 14일 프로파일 정리 완료';
    builder.cache = { enabled: true, kernel: '6.8.0-136-generic', hits: 40, misses: 60, hit_rate: 0.4, build_seconds: 80,
      warning: 'ccache 적중률 40.0% (70% 미만). 기준 캐시를 확인하세요.' };
    let reads = 0;
    const app = mount({ status: statusFixture({ jobs: [], builders: { builder24: builder } }), route: call => {
      if (call.path === '/api/builders/builder24') return response({ builder, log: `실행 로그 ${++reads} <img src=x onerror=alert(1)>` });
    } });
    await ready(); await page('빌드 작업');
    expect(screen.getByText('CVE-2099-1004 · abcdef012345')).toBeTruthy();
    expect(screen.getByText('83.0 GiB / 150.0 GiB')).toBeTruthy();
    expect(screen.getByText(/예방 여유 20 GiB 이하/)).toBeTruthy();
    expect(screen.getByText(/비활성 14일 프로파일 정리 완료/)).toBeTruthy();
    expect(screen.getByText(/40.0% 적중/)).toBeTruthy();
    expect(screen.getByText(/70% 미만/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '실시간 상태·로그' }));
    const dialog = screen.getByRole('dialog');
    await within(dialog).findByText(/실행 로그 1/);
    expect(document.querySelector('img[src="x"], [onerror]')).toBeNull();
    const statusReads = app.calls.filter(c => c.path === '/api/status').length;
    await act(async () => vi.advanceTimersByTime(5000));
    await within(dialog).findByText(/실행 로그 2/);
    expect(app.calls.filter(c => c.path === '/api/status')).toHaveLength(statusReads);
    fireEvent.click(within(dialog).getByRole('button', { name: '자동 갱신 중지' }));
    await act(async () => vi.advanceTimersByTime(15000));
    expect(reads).toBe(2);
    fireEvent.click(within(dialog).getByRole('button', { name: '새로고침' }));
    await within(dialog).findByText(/실행 로그 3/);
    fireEvent.click(within(dialog).getByRole('button', { name: '닫기' }));
    await act(async () => vi.advanceTimersByTime(10000));
    expect(reads).toBe(3);
  });

  it('실행 중인 누적 작업의 로그를 완료 전부터 자동 갱신한다', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    const status = statusFixture(); status.jobs[0].status = 'running';
    let reads = 0;
    mount({ status, route: call => call.path === '/api/jobs/2/log' ? response(`컴파일 ${++reads}`, 200, 'text/plain') : undefined });
    await ready(); await page('빌드 작업');
    fireEvent.click(screen.getByRole('button', { name: '실시간 로그' }));
    await screen.findByText('컴파일 1');
    await act(async () => vi.advanceTimersByTime(5000));
    await screen.findByText('컴파일 2');
  });

  it('이전 즉시 업데이트가 있어도 최신 누적본으로 바로 이동하며 확인한 버전을 전송한다', async () => {
    const status = statusFixture({ latest_released: { '6.8.0-136-generic': 7 } });
    const host = status.hosts[0]; host.ring = 2; host.status.version = 1;
    host.update_now_kernel = host.status.kernel; host.update_now_version = 2;
    const app = mount({ status });
    await ready(); await page('호스트');
    expect(screen.getByRole('button', { name: '즉시 업데이트 취소' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '최신 누적 v7 적용' }));
    const dialog = screen.getByRole('dialog');
    expect(dialog.textContent).toContain('v1 → 최신 누적 v7');
    expect(dialog.textContent).toContain('중간 버전을 설치하지 않고');
    expect(app.mutations()).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole('button', { name: 'v7 적용' }));
    await waitFor(() => expect(app.mutations()).toHaveLength(1));
    expect(app.mutations()[0]).toMatchObject({ path: '/api/hosts/host-1/update-now', body: { kernel: '6.8.0-136-generic', version: 7 } });
  });

  it('호스트가 쓰는 커널을 최신순으로 먼저 보이고 이전 커널은 아래 접힌 칸에 둔다', async () => {
    const base = statusFixture();
    const host = (id, kernel) => ({ ...base.hosts[0], id, hostname: id, status: { ...base.hosts[0].status, kernel } });
    const status = statusFixture({
      tracks: [{ kernel: '6.8.0-136-generic', ring_versions: { 1: 2 } }, { kernel: '6.8.0-147-generic', ring_versions: { 1: 1 } },
        { kernel: '7.0.0-28-generic', ring_versions: { 1: 6 } }, { kernel: '6.8.0-90-generic', ring_versions: { 1: 1 } }],
      hosts: [host('a', '6.8.0-147-generic'), host('b', '7.0.0-28-generic'), host('c', '6.8.0-90-generic')] });
    mount({ status });
    await ready();
    const titles = [...document.querySelectorAll('article.kernel h3')].map((h) => h.textContent);
    expect(titles).toEqual(['7.0.0-28-generic', '6.8.0-147-generic', '6.8.0-90-generic', '6.8.0-136-generic']);
    const old = document.querySelector('details.old-kernels');
    expect(old.open).toBe(false);
    expect(old.querySelector('summary').textContent).toContain('이전 커널 1개');
    expect(old.querySelector('h3').textContent).toBe('6.8.0-136-generic');
  });

  it('원인이 해결된 자동 멈춤은 오류 대신 해결됨으로 보이고 재개는 확인 뒤 요청한다', async () => {
    const hold = '수집·빌드 검토 필요: 정식 배포 6.8.0-147.147 의 Git 태그 확인 실패: exit status 128';
    const status = statusFixture({ auto: { enabled: true, paused: false, notes: { '6.8.0-136-generic': ['자동 배포 멈춤: ' + hold] } },
      tracks: [{ kernel: '6.8.0-136-generic', ring_versions: { 1: 2, 2: 0 }, auto_hold: hold, auto_hold_resolved: '수집 문제 해결' }] });
    const app = mount({ status });
    await ready();
    expect(screen.getByText('원인 해결 · 재개 대기')).toBeTruthy();
    expect(screen.getByText(/원인 해결됨 \(수집 문제 해결\)/)).toBeTruthy();
    expect(screen.queryByText('자동 배포 멈춤')).toBeNull();
    expect(screen.queryByText(/Git 태그 확인 실패/)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: '자동 재개' }));
    const dialog = screen.getByRole('dialog');
    expect(dialog.textContent).toContain('원인 해결됨: 수집 문제 해결');
    expect(app.mutations()).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole('button', { name: '재개' }));
    await waitFor(() => expect(app.mutations()).toHaveLength(1));
    expect(app.mutations()[0]).toMatchObject({ path: '/api/kernels/6.8.0-136-generic/auto', method: 'POST', body: { hold: false } });
  });
  it('최근 범위 밖 커널은 수집 권고 대신 빌드 서버 자료 삭제를 확인 뒤 요청한다', async () => {
    const status = statusFixture({ upstream: { '6.8.0-136-generic': { latest_tag: 'Ubuntu-6.8.0-147.147',
      outside: '최근 4개 ABI(147·146·145·142) 밖 · 자동 수집하지 않음' } } });
    const app = mount({ status });
    await ready(); await page('호스트');
    expect(screen.getByText(/최근 4개 ABI\(147·146·145·142\) 밖/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: '최신까지 빌드' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: '빌드 서버 자료 삭제' }));
    const dialog = screen.getByRole('dialog');
    expect(dialog.textContent).toContain('호스트에 적용된 라이브패치는 그대로');
    expect(app.mutations()).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole('button', { name: '삭제 요청' }));
    await waitFor(() => expect(app.mutations()).toHaveLength(1));
    expect(app.mutations()[0]).toMatchObject({ path: '/api/kernels/6.8.0-136-generic/purge', method: 'POST' });
  });
  it('더 최신인 승인 대기 누적본을 먼저 검토하고 중간 승인본 적용을 요구하지 않는다', async () => {
    const status = statusFixture({ latest_released: { '6.8.0-136-generic': 7 } });
    status.hosts[0].status.version = 1;
    status.jobs.unshift({ ...status.jobs[0], id: 9, version: 9, status: 'built', new_patch_ids: ['p1'] });
    const app = mount({ status });
    await ready(); await page('호스트');
    expect(screen.queryByRole('button', { name: '최신 누적 v7 적용' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: '최신 누적 v9 검토·승인' }));
    await within(screen.getByRole('dialog')).findByText(/검토할 수정/);
    expect(app.mutations()).toHaveLength(0);
  });

  it('확인 중 최신 버전이 바뀌면 다시 검토하게 하며 임의 버전으로 재요청하지 않는다', async () => {
    const status = statusFixture({ latest_released: { '6.8.0-136-generic': 7 } });
    const app = mount({ status, route: call => call.path.endsWith('/update-now') ? response({ error: '최신 승인 버전이 v8 로 바뀌었습니다.' }, 409) : undefined });
    await ready(); await page('호스트');
    fireEvent.click(screen.getByRole('button', { name: '최신 누적 v7 적용' }));
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'v7 적용' }));
    expect(await within(screen.getByRole('dialog')).findByRole('alert')).toHaveProperty('textContent', '최신 승인 버전이 v8 로 바뀌었습니다.');
    expect(app.mutations()).toHaveLength(1);
    expect(app.mutations()[0].body.version).toBe(7);
  });

  it('검증에 성공한 토큰만 탭 저장소에 저장한다', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response({ error: 'bad' }, 401)).mockResolvedValue(response(statusFixture())));
    render(<App />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText('관리자 토큰'), 'invalid');
    await user.click(screen.getByRole('button', { name: '로그인' }));
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', '토큰이 맞지 않습니다.');
    expect(sessionStorage.getItem(TOKEN_KEY)).toBeNull();
    await user.clear(screen.getByLabelText('관리자 토큰'));
    await user.type(screen.getByLabelText('관리자 토큰'), 'valid');
    await user.click(screen.getByRole('button', { name: '로그인' }));
    await ready();
    expect(sessionStorage.getItem(TOKEN_KEY)).toBe('valid');
  });

  it('재부팅은 대상 확인 뒤 한 번만 요청하며 처리 중 닫기와 Esc를 막는다', async () => {
    let finish;
    const app = mount({ route: call => call.path.endsWith('/reboot') ? new Promise(resolve => { finish = resolve; }) : undefined });
    await ready(); await page('호스트');
    fireEvent.click(screen.getByRole('button', { name: '커널 점프 → 6.8.0-147-generic' }));
    const dialog = screen.getByRole('dialog');
    expect(dialog.textContent).toContain('6.8.0-136-generic → 6.8.0-147-generic');
    expect(dialog.textContent).toContain('서비스가 중단');
    expect(app.mutations()).toHaveLength(0);
    const approve = within(dialog).getByRole('button', { name: '이 커널로 재부팅 승인' });
    fireEvent.click(approve); fireEvent.click(approve);
    expect(app.mutations()).toHaveLength(1);
    expect(app.mutations()[0].body).toEqual({ target_id: 'prepared-target-hash' });
    expect(within(dialog).getByRole('button', { name: '닫기' }).disabled).toBe(true);
    const event = new Event('cancel', { cancelable: true });
    fireEvent(dialog, event); expect(event.defaultPrevented).toBe(true);
    await act(async () => finish(response({ message: '승인됨' })));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('드레인 전이면 커널 점프가 배치 차단 뒤 재부팅 승인까지 한 번에 요청한다', async () => {
    const status = statusFixture();
    status.hosts[0].cordoned = false;
    const app = mount({ status }); await ready(); await page('호스트');
    fireEvent.click(screen.getByRole('button', { name: '커널 점프 → 6.8.0-147-generic' }));
    const dialog = screen.getByRole('dialog');
    expect(dialog.textContent).toContain('신규 VM 배치를 막고');
    fireEvent.click(within(dialog).getByRole('button', { name: '이 커널로 재부팅 승인' }));
    await waitFor(() => expect(app.mutations()).toHaveLength(2));
    expect(app.mutations().map(call => [call.path, call.body])).toEqual([
      ['/api/hosts/host-1/cordon', { on: true }],
      ['/api/hosts/host-1/reboot', { target_id: 'prepared-target-hash' }],
    ]);
  });

  it('준비된 커널이 없고 새 GA ABI가 있으면 점프 1단계로 커널 준비를 요청한다', async () => {
    const status = statusFixture();
    status.hosts[0].status.boot_target = null;
    status.upstream = { '6.8.0-136-generic': { latest_tag: 'Ubuntu-6.8.0-147.147', outside: '최근 2개 ABI 밖' } };
    const app = mount({ status }); await ready(); await page('호스트');
    expect(screen.queryByRole('button', { name: /커널 점프/ })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: '새 커널 준비 → 6.8.0-147-generic' }));
    const dialog = screen.getByRole('dialog');
    expect(dialog.textContent).toContain('재부팅하지 않으며');
    fireEvent.click(within(dialog).getByRole('button', { name: '설치 요청' }));
    await waitFor(() => expect(app.mutations()).toHaveLength(1));
    expect(app.mutations()[0]).toMatchObject({ path: '/api/hosts/host-1/prepare-kernel', body: { kernel: '6.8.0-136-generic' } });
  });

  it('커널 준비를 요청한 호스트는 요청 상태와 취소만 보여 준다', async () => {
    const status = statusFixture();
    status.hosts[0].status.boot_target = null;
    status.hosts[0].kernel_prepare_request = { kernel: '6.8.0-136-generic' };
    status.upstream = { '6.8.0-136-generic': { latest_tag: 'Ubuntu-6.8.0-147.147' } };
    mount({ status }); await ready(); await page('호스트');
    expect(screen.getByText(/6\.8\.0-147-generic 설치 요청됨/)).toBeTruthy();
    expect(screen.getByRole('button', { name: '준비 요청 취소' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: /새 커널 준비/ })).toBeNull();
  });

  it('커널 준비가 실패하면 요청이 남아 있어도 바로 다시 요청할 수 있다', async () => {
    const status = statusFixture();
    status.hosts[0].status.boot_target = null;
    status.hosts[0].kernel_prepare_request = { kernel: '6.8.0-136-generic' };
    status.hosts[0].status.kernel_prepare = { kernel: '6.8.0-136-generic', state: 'failed', error: 'fork/exec /usr/local/sbin/kpctl-prepare-kernel: no such file or directory' };
    status.upstream = { '6.8.0-136-generic': { latest_tag: 'Ubuntu-6.8.0-147.147' } };
    const app = mount({ status }); await ready(); await page('호스트');
    fireEvent.click(screen.getByRole('button', { name: '원인 해결 후 다시 준비 → 6.8.0-147-generic' }));
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: '설치 요청' }));
    await waitFor(() => expect(app.mutations()).toHaveLength(1));
    expect(app.mutations()[0]).toMatchObject({ path: '/api/hosts/host-1/prepare-kernel' });
  });

  it('이미 최신 GA ABI면 커널 준비 버튼을 보이지 않는다', async () => {
    const status = statusFixture();
    status.hosts[0].status.boot_target = null;
    status.upstream = { '6.8.0-136-generic': { latest_tag: 'Ubuntu-6.8.0-136.140' } };
    mount({ status }); await ready(); await page('호스트');
    expect(screen.queryByRole('button', { name: /새 커널 준비/ })).toBeNull();
  });

  it('VM이 남았거나 보고가 오래되면 커널 점프 대신 이유를 보여 준다', async () => {
    const status = statusFixture();
    status.hosts[0].vm_count = 3;
    mount({ status }); await ready(); await page('호스트');
    expect(screen.getByText(/6\.8\.0-147-generic 점프 불가: VM 3대 남음/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: '커널 점프 → 6.8.0-147-generic' })).toBeNull();
  });

  it('호스트 보고가 2분 넘게 없으면 커널 점프를 막는다', async () => {
    const status = statusFixture();
    status.hosts[0].last_seen = new Date(Date.parse(status.now) - 5 * 60000).toISOString();
    mount({ status }); await ready(); await page('호스트');
    expect(screen.getByText(/점프 불가: 호스트 보고가 2분 넘게 없음/)).toBeTruthy();
  });

  it('공식 커널 준비 중에는 재부팅 승인을 숨긴다', async () => {
    const status = statusFixture();
    status.hosts[0].status.kernel_prepare = { kernel: status.hosts[0].status.kernel, state: 'preparing' };
    const app = mount({ status }); await ready(); await page('호스트');
    expect(screen.getByText('공식 커널 자동 준비 중')).toBeTruthy();
    expect(screen.queryByRole('button', { name: '커널 점프 → 6.8.0-147-generic' })).toBeNull();
    expect(app.mutations()).toHaveLength(0);
  });

  it('공식 커널 준비 실패와 다음 시도를 패치 오류와 별도로 표시한다', async () => {
    const status = statusFixture();
    status.hosts[0].status.boot_target = null;
    status.hosts[0].status.kernel_prepare = { state: 'failed', error: '<script>APT 잠금</script>', next_attempt_at: '2026-11-14T06:00:00Z' };
    const app = mount({ status }); await ready(); await page('호스트');
    expect(screen.getByText('공식 커널 준비 실패: <script>APT 잠금</script>')).toBeTruthy();
    expect(screen.getByText(/다음 시도:/)).toBeTruthy();
    expect(document.querySelector('script')).toBeNull();
    expect(app.mutations()).toHaveLength(0);
  });

  it('미실행 승인의 0001 시각을 처리하고 실행 전달 뒤에는 취소하지 않는다', async () => {
    const status = statusFixture();
    status.hosts[0].reboot_approval = { id: 1, dispatched_at: '0001-01-01T00:00:00Z' };
    mount({ status }); await ready(); await page('호스트');
    expect(screen.getByRole('button', { name: '승인 취소' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: '커널 점프 → 6.8.0-147-generic' })).toBeNull();
  });

  it('이미 실행 전달된 승인은 차단 해제·취소·중복 승인에서 제외한다', async () => {
    const status = statusFixture();
    status.hosts[0].reboot_approval = { id: 1, dispatched_at: status.now };
    mount({ status }); await ready(); await page('호스트');
    expect(screen.getByRole('button', { name: '차단 해제' }).disabled).toBe(true);
    expect(screen.queryByRole('button', { name: '승인 취소' })).toBeNull();
    expect(screen.queryByRole('button', { name: '커널 점프 → 6.8.0-147-generic' })).toBeNull();
  });

  it('승급 검사 실패를 보여 주고 강제 승급은 별도 클릭을 요구한다', async () => {
    const app = mount({ route: call => call.path.endsWith('/promote') ? response(call.body.force ? { version: 2 } : { error: '카나리 관찰 시간 부족' }, call.body.force ? 200 : 409) : undefined });
    await ready();
    fireEvent.click(screen.getByRole('button', { name: '링 2 승급' }));
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: '승급', exact: true }));
    await screen.findByText('카나리 관찰 시간 부족');
    expect(app.mutations().map(call => call.body)).toEqual([{ ring: 2, force: false, expected_version: 2 }]);
    fireEvent.click(screen.getByRole('button', { name: '검사를 무시하고 승급' }));
    await screen.findByText('링 2에 v2 배포를 시작했습니다.');
    expect(app.mutations().map(call => call.body)).toEqual([{ ring: 2, force: false, expected_version: 2 }, { ring: 2, force: true, expected_version: 2 }]);
  });

  it('강제 승급 전 목표 버전이 바뀌면 기존 확인을 폐기한다', async () => {
    const status = statusFixture();
    const app = mount({ status, route: call => {
      if (!call.path.endsWith('/promote')) return;
      if (!call.body.force) return response({ error: '카나리 관찰 시간 부족' }, 409);
      status.tracks[0].ring_versions[1] = 3;
      return response({ error: '링 1의 목표 버전이 v3로 바뀌었습니다.' }, 412);
    } });
    await ready();
    fireEvent.click(screen.getByRole('button', { name: '링 2 승급' }));
    const dialog = within(screen.getByRole('dialog'));
    fireEvent.click(dialog.getByRole('button', { name: '승급', exact: true }));
    fireEvent.click(await dialog.findByRole('button', { name: '검사를 무시하고 승급' }));
    await dialog.findByText('링 1의 목표 버전이 v3로 바뀌었습니다.');
    expect(dialog.getByRole('button', { name: '승급', exact: true }).disabled).toBe(true);
    expect(dialog.queryByRole('button', { name: '검사를 무시하고 승급' })).toBeNull();
    expect(app.mutations().map(call => call.body.expected_version)).toEqual([2, 2]);
    fireEvent.click(dialog.getByRole('button', { name: '닫기' }));
    fireEvent.click(screen.getByRole('button', { name: '링 2 승급' }));
    expect(await screen.findByText(/v3를 링 2에 배포합니다/)).toBeTruthy();
  });

  it('CVE의 미수집·정보 부족과 신뢰 범위를 표시하며 외부 문자열을 HTML로 실행하지 않는다', async () => {
    mount({ coverage: coverageFixture({ source_stale: true }) }); await ready(); await page('CVE 현황');
    await screen.findByText('<img src=x onerror=alert(1)>');
    // 외부 문자열이 HTML로 해석되지 않았는지만 봅니다. (사이드바 로고 같은 앱 자체 <img>는 대상이 아님)
    expect(document.querySelector('img[src="x"], [onerror]')).toBeNull();
    expect(screen.getByText('공식 정보 부족 99')).toBeTruthy();
    expect(screen.getByText(/목록이 오래됐거나/)).toBeTruthy();
    expect(screen.getByText(/모든 수정과 공격 차단이 검증됐다는 뜻이 아닙니다/)).toBeTruthy();
  });

  it('CVE 표는 15건 단위로 다음·이전 페이지를 요청한다', async () => {
    const app = mount({ route: call => {
      if (!call.path.startsWith('/api/coverage?')) return;
      const offset = Number(new URLSearchParams(call.path.split('?')[1]).get('offset'));
      return response(coverageFixture({ total: 40, offset }));
    } });
    await ready(); await page('CVE 현황');
    await screen.findByText('1 / 3 페이지');
    expect(screen.getByRole('button', { name: '이전' })).toHaveProperty('disabled', true);
    fireEvent.click(screen.getByRole('button', { name: '다음' }));
    await screen.findByText('2 / 3 페이지');
    fireEvent.click(screen.getByRole('button', { name: '마지막' }));
    await screen.findByText('3 / 3 페이지');
    expect(screen.getByRole('button', { name: '다음' })).toHaveProperty('disabled', true);
    const offsets = app.calls.filter(call => call.path.startsWith('/api/coverage?')).map(call => new URLSearchParams(call.path.split('?')[1]).get('offset'));
    expect([...new Set(offsets)]).toEqual(['0', '15', '30']);
  });

  it('모바일 카드 보기용으로 표의 각 칸에 열 이름을 붙인다', async () => {
    mount(); await ready(); await page('호스트');
    const labels = [...document.querySelector('.rtable tbody tr').children].map(td => td.dataset.label);
    expect(labels).toEqual(['호스트', '커널', '적용/목표', '보안·서명', '다음 재부팅 커널', '운영', '호스트 조작']);
    await page('CVE 현황');
    const cve = await screen.findByRole('link', { name: 'CVE-2026-43083' });
    expect(cve.closest('td').dataset.label).toBe('CVE');
  });

  it('공식 목록 조회 실패를 보호 성공으로 표시하지 않는다', async () => {
    mount({ route: call => call.path.startsWith('/api/coverage?') ? response({ error: '공식 목록 없음' }, 503) : undefined });
    await ready(); await page('CVE 현황');
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', '공식 목록 없음');
  });

  it('호스트 선택을 바꾼 뒤 늦게 도착한 이전 CVE 응답을 버린다', async () => {
    let finish;
    const status = statusFixture(); status.hosts.push({ ...status.hosts[0], id: 'host-2', hostname: 'second' });
    mount({ status, route: call => {
      if (call.path.startsWith('/api/coverage?')) return call.path.includes('host=host-1') ? new Promise(resolve => { finish = resolve; }) : response(coverageFixture({ base_version: 'NEW-BASE' }));
    } });
    await ready(); await page('CVE 현황');
    await waitFor(() => expect(finish).toBeTypeOf('function'));
    // shadcn(Base UI) Select: 트리거를 열고 항목을 고릅니다.
    const user = userEvent.setup();
    await user.click(screen.getByRole('combobox', { name: '대조할 호스트' }));
    await user.click(await screen.findByRole('option', { name: 'second' }));
    await screen.findByText(/NEW-BASE/);
    await act(async () => finish(response(coverageFixture({ base_version: 'STALE-BASE' }))));
    expect(screen.queryByText(/STALE-BASE/)).toBeNull();
  });

  it('주기 상태 갱신이 느린 동일 CVE 요청을 취소하거나 중복하지 않는다', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    let finish;
    const app = mount({ route: call => call.path.startsWith('/api/coverage?') ? new Promise(resolve => { finish = resolve; }) : undefined });
    await ready(); await page('CVE 현황');
    await waitFor(() => expect(finish).toBeTypeOf('function'));
    await act(async () => { vi.advanceTimersByTime(20000); });
    const calls = app.calls.filter(call => call.path.startsWith('/api/coverage?'));
    expect(calls).toHaveLength(1); expect(calls[0].signal.aborted).toBe(false);
    await act(async () => finish(response(coverageFixture())));
    await screen.findByText('공식 정보 부족 99');
  });

  it('설정 편집 중 폴링을 멈추고 숫자와 링 시간을 정확히 저장한다', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    const app = mount({ route: call => call.path === '/api/settings' && call.method === 'POST' ? response({ ...settingsFixture(), current: call.body }) : undefined });
    await ready(); await page('설정');
    const field = await screen.findByLabelText('자동 승급 전 관찰');
    fireEvent.change(field, { target: { value: '1500' } });
    const reads = app.calls.filter(call => call.path === '/api/status').length;
    await act(async () => vi.advanceTimersByTime(20000));
    expect(app.calls.filter(call => call.path === '/api/status')).toHaveLength(reads);
    expect(field.value).toBe('1500');
    fireEvent.click(screen.getByRole('button', { name: '저장', exact: true }));
    await waitFor(() => expect(app.mutations()).toHaveLength(1));
    expect(app.mutations()[0].body).toMatchObject({ auto_soak_minutes: 1500, min_soak_minutes: { 2: 1440 }, host_stale_minutes: 10, job_timeout_minutes: 180 });
    expect(app.mutations()[0].path).toBe('/api/settings');
  });

  it('빈 관찰 시간을 0으로 저장하지 않는다', async () => {
    const app = mount(); await ready(); await page('설정');
    fireEvent.change(await screen.findByLabelText('링 2 승급 전 최소 관찰'), { target: { value: '' } });
    fireEvent.submit(screen.getByRole('button', { name: '저장', exact: true }).closest('form'));
    await waitFor(() => expect(screen.getAllByRole('alert').some(node => node.textContent.includes('정수를 넣으세요'))).toBe(true));
    expect(app.mutations()).toHaveLength(0);
  });

  it('설정 되돌리기는 편집 초안을 버리고 서버의 최신 값을 다시 읽는다', async () => {
    let reads = 0;
    const app = mount({ route: call => {
      if (call.path !== '/api/settings') return;
      const settings = settingsFixture();
      if (++reads > 1) settings.current.auto_soak_minutes = 1700;
      return response(settings);
    } });
    await ready(); await page('설정');
    fireEvent.change(await screen.findByLabelText('자동 승급 전 관찰'), { target: { value: '1500' } });
    fireEvent.click(screen.getByRole('button', { name: '되돌리기', exact: true }));
    await waitFor(() => expect(screen.getByLabelText('자동 승급 전 관찰').value).toBe('1700'));
    expect(app.mutations()).toHaveLength(0);
  });

  it('다른 화면의 401도 토큰을 지우고 로그인으로 돌아간다', async () => {
    mount({ route: call => call.path === '/api/audit' ? response({ error: 'unauthorized' }, 401) : undefined });
    await ready(); await page('감사 로그');
    await screen.findByLabelText('관리자 토큰');
    expect(sessionStorage.getItem(TOKEN_KEY)).toBeNull();
    expect(screen.queryByRole('navigation')).toBeNull();
  });

  it('작업 검토·diff·감사 로그를 React 화면으로 제공한다', async () => {
    const status = statusFixture(); status.jobs[0].new_patch_ids = ['p1'];
    mount({ status }); await ready(); await page('빌드 작업');
    fireEvent.click(screen.getByRole('button', { name: '보기', exact: true }));
    await screen.findByText('검토할 수정', { exact: false });
    fireEvent.click(screen.getByRole('button', { name: '닫기' }));
    await page('패치'); await screen.findByText('검토할 수정');
    fireEvent.click(screen.getByRole('button', { name: 'diff', exact: true }));
    await screen.findByText('+safe', { exact: false });
    fireEvent.click(screen.getByRole('button', { name: '닫기' }));
    await page('감사 로그');
    await screen.findByText('second first', { exact: false, normalizer: text => text.replace(/\s+/g, ' ').trim() });
  });
});


describe('출시 전 작업 승인', () => {
  it('출시 전 표시와 명시 동의를 확인한 뒤 prerelease 플래그를 전송한다', async () => {
    const status = statusFixture();
    status.jobs = [{ ...status.jobs[0], id: 12, version: -1, prerelease: true, prerelease_version: 1, status: 'built', new_patch_ids: ['p1'] }];
    const app = mount({ status });
    await ready();
    expect(screen.getByText(/출시 전 pre1/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '검토', exact: true }));
    const dialog = screen.getByRole('dialog');
    const approve = within(dialog).getByRole('button', { name: '승인 — 링 1 에 배포' });
    expect(approve.disabled).toBe(true);
    await within(dialog).findByText(/검토할 수정/);
    fireEvent.click(within(dialog).getByLabelText('출시 전 작업의 VM 시험과 배포를 명시적으로 승인합니다'));
    await waitFor(() => expect(approve.disabled).toBe(false));
    fireEvent.click(approve);
    await waitFor(() => expect(app.mutations()).toHaveLength(1));
    expect(app.mutations()[0]).toMatchObject({ path: '/api/jobs/12/approve', body: { prerelease: true } });
  });
});
