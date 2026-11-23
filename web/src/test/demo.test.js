// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
import { createDemoStore } from '../../dev/store.js';
import { DEMO_TOKEN } from '../../dev/data.js';
import viteConfig from '../../vite.config.js';

describe('격리된 개발 데이터 API', () => {
  function fixture(options) {
    const store = createDemoStore(options);
    return (method, path, body = {}) => store.handle(method, path, body, DEMO_TOKEN);
  }
  it('데모 토큰만 허용하고 조회 응답은 내부 상태와 분리한다', () => {
    const store = createDemoStore();
    expect(store.handle('GET', '/api/status').status).toBe(401);
    expect(store.handle('POST', '/api/dev/reset', {}, 'production-token').status).toBe(401);
    const first = store.handle('GET', '/api/status', {}, DEMO_TOKEN);
    first.body.hosts.length = 0;
    expect(store.handle('GET', '/api/status', {}, DEMO_TOKEN).body.hosts.length).toBe(6);
  });
  it('승인·관찰 시간·명시적 강제 승급과 가상 에이전트 적용을 재현한다', () => {
    const api = fixture();
    expect(api('POST', '/api/jobs/6/approve').status).toBe(200);
    expect(api('POST', '/api/jobs/6/approve').status).toBe(409);
    const path = '/api/kernels/6.8.0-136-generic/promote';
    expect(api('POST', path, { ring: 2, force: true, expected_version: 2 }).status).toBe(412);
    expect(api('POST', path, { ring: 2, force: false, expected_version: 3 }).status).toBe(409);
    expect(api('POST', path, { ring: 2, force: true, expected_version: 3 }).status).toBe(200);
    expect(api('GET', '/api/status').body.hosts.find(h => h.id === 'demo-0-2').status.version).toBe(3);
    expect(api('GET', '/api/audit').body).toContain('가상 승인');
  });
  it('재부팅 대상·VM·중복 승인을 검사하며 실제 부팅은 하지 않는다', () => {
    const api = fixture(), path = '/api/hosts/demo-0-2/reboot';
    const before = api('GET', '/api/status').body.hosts.find(h => h.id === 'demo-0-2');
    expect(api('POST', path, { target_id: 'wrong-target' }).status).toBe(409);
    expect(api('POST', path, { target_id: before.status.boot_target.id }).status).toBe(200);
    expect(api('POST', path, { target_id: before.status.boot_target.id }).status).toBe(409);
    const after = api('GET', '/api/status').body.hosts.find(h => h.id === before.id);
    expect(after.status.boot_id).toBe(before.status.boot_id);
    expect(after.status.kernel).toBe(before.status.kernel);
    expect(after.reboot_approval.dispatched_at).toBe('0001-01-01T00:00:00Z');
    expect(api('POST', path, { cancel: true }).status).toBe(200);
    expect(api('POST', '/api/hosts/demo-0-1/reboot', { target_id: 'demo-target-demo-0-1' }).status).toBe(409);
  });
  it('CVE 검색·필터·페이지·오류 및 빈 환경을 재현한다', () => {
    const api = fixture(), path = '/api/coverage?host=demo-0-1';
    expect(api('GET', path + '&state=all').body.rows).toHaveLength(15);
    expect(api('GET', path + '&state=all&offset=135').body.rows).toHaveLength(10);
    expect(api('GET', path + '&state=all&q=CVE-2099-1000').body.rows).toHaveLength(1);
    expect(api('GET', path + '&state=unknown').body.rows.every(row => row.status === 'unknown')).toBe(true);
    expect(api('POST', '/api/dev/reset', { scenario: 'source-error' }).status).toBe(200);
    expect(api('GET', path).status).toBe(503);
    api('POST', '/api/dev/reset', { scenario: 'empty' });
    expect(api('GET', '/api/status').body.hosts).toHaveLength(0);
    expect(api('POST', '/api/dev/reset', { scenario: 'invalid' }).status).toBe(400);
  });
  it('목록 수정·설정 저장·가상 빌드·롤백을 메모리 안에서 처리한다', () => {
    const api = fixture(), kernel = '/api/kernels/6.8.0-136-generic';
    const patch = api('GET', kernel + '/patches').body[0];
    api('POST', '/api/patches/' + patch.id + '/state', { state: 'disabled' });
    api('POST', kernel + '/build');
    const job = api('GET', '/api/status').body.jobs[0];
    expect(job.status).toBe('built'); expect(job.patch_ids).not.toContain(patch.id);
    const settings = api('GET', '/api/settings').body.current;
    settings.auto_soak_minutes = 1500;
    expect(api('POST', '/api/settings', settings).body.current.auto_soak_minutes).toBe(1500);
    settings.host_stale_minutes = 0;
    expect(api('POST', '/api/settings', settings).status).toBe(400);
    expect(api('POST', kernel + '/rollback', { version: 999 }).status).toBe(400);
    expect(api('POST', kernel + '/rollback', { version: 0 }).status).toBe(200);
    expect(Object.values(api('GET', '/api/status').body.tracks[0].ring_versions)).toEqual([0, 0]);
  });
  it('알 수 없는 API도 운영 네트워크로 전달하지 않는다', () => {
    const fetch = vi.fn(() => { throw new Error('unexpected network'); });
    vi.stubGlobal('fetch', fetch);
    expect(fixture()('POST', '/api/something-new').status).toBe(404);
    expect(fetch).not.toHaveBeenCalled();
  });
  it('가상 모드와 실제 API 프록시를 동시에 켤 수 없다', () => {
    vi.stubEnv('KPCTL_DEV_URL', 'https://example.invalid');
    try { expect(() => viteConfig({ command: 'serve', mode: 'mock' })).toThrow('함께 설정할 수 없습니다'); }
    finally { vi.unstubAllEnvs(); }
    const config = viteConfig({ command: 'serve', mode: 'mock' });
    expect(config.server.proxy).toBeUndefined();
    expect(config.plugins.some(plugin => plugin.name === 'kpctl-demo-api')).toBe(true);
  });
  it('혼합 보안 상태·옛 키·MOK 등록과 콘솔 승인 대기를 표시할 데이터를 제공한다', () => {
    const api = fixture(), status = api('GET', '/api/status').body;
    const host = id => status.hosts.find(item => item.id === id);
    expect(host('demo-0-1').status).toMatchObject({ firmware: 'uefi', secure_boot: 'on', lockdown: 'integrity', sig_enforce: 'off', signature_required: true });
    expect(host('demo-0-1').rollout_eligibility).toMatchObject({ status: 'eligible', key_id: 'prod-2026' });
    expect(host('demo-0-2').status).toMatchObject({ firmware: 'bios', signature_required: false, enrolled_certs: { 'prod-2026': 'unknown' } });
    expect(host('demo-1-1').rollout_eligibility).toMatchObject({ status: 'eligible', key_id: 'prod-2025' });
    expect(host('demo-1-2').rollout_eligibility).toMatchObject({ status: 'blocked_mok_missing', reason: 'MOK 등록 필요' });
    expect(host('demo-transition').status.mok_pending).toBe(true);
    expect(host('demo-transition').rollout_eligibility.reason).toContain('다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요');
    expect(host('demo-offline').status.security_warning).toContain('서명 필요로 판단');
    expect(host('demo-offline').rollout_eligibility).toMatchObject({ status: 'eligible', key_id: 'prod-2026' });
    expect(host('demo-offline').rollout_eligibility.warning).toContain('이전 에이전트');
  });
  it('공개 서명 현황과 만료 경고는 조회 사본으로 제공하고 키 파일·명령을 내보내지 않는다', () => {
    const api = fixture(), signing = api('GET', '/api/signing').body;
    expect(signing.mode).toBe('always');
    expect(signing.keys.find(key => key.id === 'prod-2026')).toMatchObject({ active: true, enrolled_hosts: 1 });
    expect(signing.keys.find(key => key.id === 'prod-2025')).toMatchObject({ active: false, enrolled_hosts: 1, warning: '인증서 만료가 30일 이내입니다' });
    expect(signing.warnings[0]).toContain('retired-2024');
    const settings = api('GET', '/api/settings').body;
    expect(settings.signing).toEqual(signing);
    expect(JSON.stringify(settings)).not.toMatch(/sign_command|private_key|\.priv|\/etc\//);
    signing.keys[0].active = false;
    expect(api('GET', '/api/signing').body.keys[0].active).toBe(true);
    expect(api('POST', '/api/settings', { ...settings.current, signing: { mode: 'never' } }).status).toBe(400);
    api('DELETE', '/api/hosts/demo-offline');
    expect(api('GET', '/api/signing').body.warnings).toEqual([]);
    api('POST', '/api/dev/reset', { scenario: 'empty' });
    expect(api('GET', '/api/signing').body.keys.every(key => key.enrolled_hosts === 0)).toBe(true);
    api('POST', '/api/dev/reset', { scenario: 'healthy' });
    expect(api('GET', '/api/status').body.hosts.every(host => host.rollout_eligibility.status === 'eligible')).toBe(true);
    expect(api('GET', '/api/signing').body.keys.every(key => !key.warning)).toBe(true);
  });
  it('키별·모드별 VM 증거를 제공하며 재승인 때 실패한 시험을 다시 통과시킨다', () => {
    const api = fixture(), before = api('GET', '/api/status').body.jobs.find(job => job.id === 6);
    expect(before.vm_test.status).toBe('failed');
    expect(before.vm_test.steps.some(step => step.name === 'smoke' && step.status === 'failed')).toBe(true);
    expect(before.vm_test.steps.some(step => step.name === 'cleanup' && step.status === 'passed')).toBe(true);
    expect(api('POST', '/api/jobs/6/approve').status).toBe(200);
    const approved = api('GET', '/api/status').body.jobs.find(job => job.id === 6);
    expect(approved.vm_test.status).toBe('passed');
    expect(approved.sha256).toBe(approved.signing_artifacts[approved.active_signing_key].sha256);
    expect(new Set(approved.vm_test.steps.map(step => step.key_id))).toEqual(new Set(['prod-2026', 'prod-2025']));
    expect(new Set(approved.vm_test.steps.map(step => step.mode))).toEqual(new Set(['sb_on', 'bios']));
  });
  it('출시 전 승인은 명시 플래그와 VM 시험을 요구하고 정식 버전·최신 배포를 유지한다', () => {
    const api = fixture(), kernel = '6.8.0-136-generic';
    expect(api('POST', '/api/jobs/7/approve').status).toBe(409);
    expect(fixture({ testVMEnabled: false })('POST', '/api/jobs/7/approve', { prerelease: true }).status).toBe(409);
    const settings = api('GET', '/api/settings').body.current;
    api('POST', '/api/settings', { ...settings, auto_enabled: true });
    expect(api('GET', '/api/status').body.jobs.find(job => job.id === 7).status).toBe('built');
    expect(api('POST', '/api/jobs/7/approve', { prerelease: true }).status).toBe(200);
    const status = api('GET', '/api/status').body, track = status.tracks.find(item => item.kernel === kernel);
    expect(track.ring_versions).toEqual({ 1: 2, 2: 0 });
    expect(track.prerelease_ring_versions).toEqual({ 1: -1 });
    expect(status.latest_released[kernel]).toBe(2);
    expect(status.hosts.find(host => host.id === 'demo-0-1').status).toMatchObject({ version: -1, loaded: [{ name: 'kpctl_6_8_0_136_generic_pre1' }] });
    expect(status.auto.notes[kernel][0]).toContain('자동 승인·승급 보류');
    expect(status.jobs.find(job => job.id === 6).status).toBe('built');
  });
  it('출시 전 승급·롤백은 별도 플래그로 수행하고 즉시 업데이트로 우회할 수 없다', () => {
    const api = fixture(), kernel = '/api/kernels/6.8.0-136-generic';
    api('POST', '/api/hosts/demo-0-2/update-now', { kernel: '6.8.0-136-generic', version: 2 });
    api('POST', '/api/jobs/7/approve', { prerelease: true });
    expect(api('POST', kernel + '/promote', { ring: 2, force: true }).status).toBe(409);
    expect(api('POST', kernel + '/promote', { ring: 2, force: true, prerelease: true }).status).toBe(200);
    const host = api('GET', '/api/status').body.hosts.find(item => item.id === 'demo-0-2');
    expect(host.status.version).toBe(-1);
    expect(api('POST', '/api/hosts/demo-0-2/update-now', { version: -1 }).status).toBe(400);
    expect(api('POST', '/api/hosts/demo-0-2/update-now', { version: 2 }).status).toBe(409);
    expect(api('POST', '/api/hosts/demo-0-2/update-now', { cancel: true }).status).toBe(200);
    expect(api('POST', kernel + '/rollback', { version: -1 }).status).toBe(409);
    expect(api('POST', kernel + '/rollback', { version: -1, prerelease: true }).status).toBe(200);
    expect(api('POST', kernel + '/rollback', { version: 2 }).status).toBe(200);
    const status = api('GET', '/api/status').body;
    expect(status.tracks[0].prerelease_ring_versions).toEqual({});
    expect(status.hosts.find(item => item.id === 'demo-0-2').status.version).toBe(2);
  });
  it('MOK 제외 호스트의 기존 모듈은 유지하며 건강한 호스트의 승급은 막지 않는다', () => {
    const api = fixture(), kernel = '/api/kernels/7.0.0-28-generic';
    const original = api('GET', '/api/status').body.hosts.find(host => host.id === 'demo-1-2');
    const settings = api('GET', '/api/settings').body.current;
    api('POST', '/api/settings', { ...settings, min_soak_minutes: { 2: 0 } });
    api('POST', kernel + '/build');
    const job = api('GET', '/api/status').body.jobs[0];
    expect(api('POST', `/api/jobs/${job.id}/approve`).status).toBe(200);
    api('GET', '/api/status');
    const promoted = api('POST', kernel + '/promote', { ring: 2 });
    expect(promoted.status).toBe(200);
    expect(promoted.body.excluded_count).toBe(2);
    expect(promoted.body.excluded_hosts.map(host => host.reason)).toContain('MOK 등록 필요');
    const status = api('GET', '/api/status').body;
    expect(status.hosts.find(host => host.id === original.id).status.loaded).toEqual(original.status.loaded);
    expect(status.hosts.find(host => host.id === original.id).status.version).toBe(3);
    expect(status.hosts.find(host => host.id === 'demo-1-1').status.version).toBe(4);
    expect(api('POST', kernel + '/rollback', { version: 0 }).status).toBe(200);
    expect(api('GET', '/api/status').body.hosts.find(host => host.id === original.id).status.loaded).toEqual([]);
  });
  it('정식·출시 전 빌드 번호와 누적 입력을 분리하고 오래된 출시 전 입력은 거부한다', () => {
    const api = fixture(), kernel = '/api/kernels/6.8.0-136-generic';
    const patches = api('GET', kernel + '/patches').body, prePatch = patches.find(patch => patch.prerelease);
    api('POST', kernel + '/build');
    const formal = api('GET', '/api/status').body.jobs[0];
    expect(formal.version).toBe(4); expect(formal.patch_ids).not.toContain(prePatch.id);
    const official = patches.find(patch => !patch.prerelease);
    api('POST', `/api/patches/${official.id}/state`, { state: 'disabled' });
    api('POST', kernel + '/build', { prerelease: true });
    const status = api('GET', '/api/status').body, preview = status.jobs[0];
    expect(preview).toMatchObject({ prerelease: true, version: -2, prerelease_version: 2 });
    expect(preview.patch_ids).toContain(prePatch.id); expect(preview.patch_ids).not.toContain(official.id);
    expect(status.jobs.find(job => job.id === formal.id).status).toBe('built');
    api('POST', `/api/patches/${official.id}/state`, { state: 'active' });
    expect(api('POST', `/api/jobs/${preview.id}/approve`, { prerelease: true }).status).toBe(409);
  });
  it('서명 never 모드에서도 배포 제외는 기존 보호를 보존한다', () => {
    const api = fixture({ signingMode: 'never' }), status = api('GET', '/api/status').body;
    expect(status.hosts.find(host => host.id === 'demo-1-1')).toMatchObject({ status: { version: 3 }, rollout_eligibility: { status: 'blocked_signing_disabled' } });
    expect(status.hosts.find(host => host.id === 'demo-0-2').rollout_eligibility.status).toBe('eligible');
  });
});
