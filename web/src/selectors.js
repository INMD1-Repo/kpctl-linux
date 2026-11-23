export const ver = value => value < 0 ? '출시 전 pre' + Math.abs(value) : value ? 'v' + value : '-';
export const isSet = value => Boolean(value && !value.startsWith('0001'));
export const tagVersion = tag => (tag || '').replace(/^Ubuntu-/, '');
export const localTime = value => isSet(value) ? new Date(value).toLocaleString('ko-KR') : '-';
export const JOB_STATUS = { queued: ['대기', ''], running: ['빌드중', 'warn'], built: ['승인대기', 'warn'], failed: ['실패', 'bad'], released: ['배포됨', 'ok'], superseded: ['폐기', ''] };
export const PATCH_STATE = { active: ['활성', 'ok'], rejected: ['제외 · 검토 필요', 'bad'], disabled: ['끔', ''] };
export const COVERAGE_STATE = {
  admin_excluded: ['미해결 · 관리자 제외', 'bad'],
  included: ['실행 모듈에 포함', ''], pending: ['수집됨 · 적용 대기', 'warn'], partial: ['일부 포함 · 추가 조치 필요', 'bad'],
  vendor_fix_unknown: ['공식 수정버전 미확인', 'warn'], not_collected: ['미수집', 'bad'], disabled: ['제외 · 검토 필요', 'warn'],
  unpatchable: ['빌드 불가 판정 있음', 'bad'], base_fixed: ['기준 커널에 수정본 포함', ''], outside_range: ['공식 영향 범위 밖', ''], unknown: ['공식 정보 부족', 'warn'],
};
export function ago(time, now) {
  if (!isSet(time)) return '-';
  const seconds = Math.max(0, (new Date(now) - new Date(time)) / 1000);
  if (seconds < 60) return Math.round(seconds) + '초 전';
  if (seconds < 3600) return Math.round(seconds / 60) + '분 전';
  if (seconds < 172800) return Math.round(seconds / 3600) + '시간 전';
  return Math.round(seconds / 86400) + '일 전';
}
export const trackTarget = (track, ring) => track?.prerelease_ring_versions?.[ring] || track?.ring_versions?.[ring] || 0;
export const ringTarget = (status, host) => trackTarget(status.tracks.find(t => t.kernel === host.status.kernel), host.ring);
export const forcedVersion = host => host.update_now_kernel === host.status.kernel ? host.update_now_version || 0 : 0;
export const hostTarget = (status, host) => { const target = ringTarget(status, host); return target < 0 ? target : Math.max(target, forcedVersion(host)); };
export const latestFor = (status, host) => status.latest_released?.[host.status.kernel] || 0;
export function isHWE(host) {
  const pkg = (host.status.kernel_signature || '').split(/\s+/)[1] || '';
  return pkg.includes('~') && /^(5\.15\.0|6\.8\.0|7\.0\.0)-.*-generic$/.test(host.status.kernel);
}
export function hostState(status, host) {
  if ((new Date(status.now) - new Date(host.last_seen)) / 1000 > (status.host_stale_minutes || 10) * 60) return ['연락끊김', 'bad'];
  if (host.status.error) return ['오류', 'bad'];
  if (isHWE(host)) return ['HWE 미지원', ''];
  if (host.rollout_eligibility?.status?.startsWith('blocked_')) return ['배포 제외', 'warn'];
  if (host.status.version !== hostTarget(status, host)) return ['적용대기', 'warn'];
  if ((host.status.loaded || []).some(p => p.transition)) return ['전환중', 'warn'];
  return ['정상', 'ok'];
}
// 화면의 이전 보고 fallback도 미확인 신호를 안전하게 표시합니다. 실제 배포 판단은 컨트롤러가 합니다.
export function hostSecurity(host) {
  const status = host.status || {};
  const signals = [
    ['secure_boot', ['on', 'off']],
    ['lockdown', ['none', 'integrity', 'confidentiality']],
    ['sig_enforce', ['on', 'off']],
  ];
  const missing = signals.filter(([field, known]) => !known.includes(status[field])).map(([field]) => field);
  const required = status.signature_required || status.secure_boot === 'on' || ['integrity', 'confidentiality'].includes(status.lockdown) || status.sig_enforce === 'on' || missing.length > 0;
  return { required, warning: status.security_warning || (missing.length ? missing.join(', ') + ' 상태 미확인: 서명이 필요한 것으로 표시합니다.' : '') };
}
export function pkgVersion(host) {
  const fields = (host.status.kernel_signature || '').split(/\s+/);
  return fields[0] === 'Ubuntu' && fields[1]?.includes('-') ? fields[1].slice(0, fields[1].lastIndexOf('-')) : '';
}
export function cmpVer(a, b) {
  const x = a.split(/[.\-~+]/), y = b.split(/[.\-~+]/);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const first = Number(x[i] || 0) || 0, second = Number(y[i] || 0) || 0;
    if (first !== second) return first < second ? -1 : 1;
  }
  return 0;
}
export const openJob = (status, kernel) => status.jobs.find(j => j.kernel === kernel && !j.prerelease && ['queued', 'running', 'built'].includes(j.status));
export const coveredTag = (status, host) => status.released_tags?.[host.status.kernel]?.[host.status.version] || '';
export function knownKernels(status) {
  return [...new Set([...status.tracks.map(t => t.kernel), ...status.hosts.map(h => h.status.kernel), ...status.unpatchable.map(u => u.kernel)].filter(Boolean))].sort();
}
export function builderNote(status, kernel) {
  const series = [['5.15.0-', 'jammy'], ['6.8.0-', 'noble'], ['7.0.0-', 'resolute']].find(([prefix]) => kernel.startsWith(prefix) && kernel.endsWith('-generic'))?.[1] || '';
  const recent = Object.values(status.builders || {}).filter(b => (b.series === series || b.kernels?.includes(kernel) || !b.series) && new Date(status.now) - new Date(b.last_seen) < 300000);
  if (!recent.length) return (series || kernel) + ' 빌드 서버의 최근 조회가 없습니다. 긴 빌드 중이면 조회가 지연될 수 있으므로 로그를 확인하세요.';
  if (!recent.some(b => b.can_refresh)) return recent.map(b => b.name).join(', ') + ' 가 수집 요청을 지원하지 않습니다. 빌더 업데이트가 필요합니다.';
  return '';
}
