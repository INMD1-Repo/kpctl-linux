export const DEMO_TOKEN = 'demo-admin-token';
export const SCENARIOS = ['mixed', 'healthy', 'empty', 'source-error'];
const kernels = ['6.8.0-136-generic', '7.0.0-28-generic'];
export const ago = (minutes = 0) => new Date(Date.now() - minutes * 60000).toISOString();
export const kernelVersions = { [kernels[0]]: 2, [kernels[1]]: 3 };
export const moduleName = (kernel, version) => `kpctl_${kernel.replaceAll(/[.-]/g, '_')}${version < 0 ? `_pre${-version}` : `_v${version}`}`;
const expires = days => new Date(Date.now() + days * 86400000).toISOString();
export const demoSigningKeys = ['prod-2026', 'prod-2025'];
const demoSHA = (version, index) => (Math.abs(version) * 10 + index + 1).toString(16).padStart(64, '0');
export function setDemoVMEvidence(job, status = 'passed') {
  const modes = ['sb_on', 'bios'];
  job.module_name = moduleName(job.kernel, job.version);
  job.active_signing_key = demoSigningKeys[0];
  job.sha256 = demoSHA(job.version, 0);
  const result = (key, index) => ({ status, sha256: demoSHA(job.version, index), modes,
    started_at: ago(12), finished_at: ago(11), ...(status === 'failed' && { error: '가상 smoke 명령 실패 · 정리는 완료했습니다.' }),
    steps: modes.flatMap(mode => ['boot', 'negative_signature', 'load_previous', 'load_new', 'replace', 'smoke', 'rollback', 'cleanup', 'kernel_log'].map(name => ({
      name, mode, key_id: key,
      status: name === 'negative_signature' && mode !== 'sb_on' || name === 'rollback' && status === 'failed' ? 'skipped' : name === 'smoke' && status === 'failed' ? 'failed' : 'passed',
      detail: `가상 ${name} 단계 · 실제 커널/VM 시험 결과가 아닙니다.`,
    }))) });
  job.signing_artifacts = Object.fromEntries(demoSigningKeys.map((key, index) => [key, {
    key_id: key, file: `${job.module_name}.ko`, sha256: demoSHA(job.version, index), signed: true, vm_test: result(key, index),
  }]));
  job.vm_test = { ...job.signing_artifacts[demoSigningKeys[0]].vm_test,
    steps: Object.values(job.signing_artifacts).flatMap(artifact => artifact.vm_test.steps) };
  return job;
}
export function applyVersion(host, version) {
  host.status.version = version;
  host.status.loaded = version ? [{ name: moduleName(host.status.kernel, version), enabled: true, transition: false }] : [];
}
export function initialData(scenario = 'mixed') {
  const hosts = kernels.flatMap((kernel, i) => [1, 2].map(ring => {
    const id = `demo-${i}-${ring}`;
    const host = { id, hostname: `demo-ubuntu${i ? 26 : 24}-${ring}`, ring, last_seen: ago(), cordoned: ring === 2,
      vm_count: ring === 2 ? 0 : 4, reboot_policy: 'drain',
      status: { kernel, kernel_signature: `Ubuntu ${i ? '7.0.0-28.28' : '6.8.0-136.136'}-generic ${i ? '7.0.0' : '6.8.12'}`, boot_id: `demo-boot-${id}`,
        firmware: i === 0 && ring === 2 ? 'bios' : 'uefi', secure_boot: i === 0 && ring === 2 ? 'off' : 'on',
        lockdown: i === 0 && ring === 2 ? 'none' : 'integrity', sig_enforce: 'off',
        signature_required: !(i === 0 && ring === 2), security_warning: '', mok_pending: false,
        enrolled_certs: i === 0 && ring === 2 ? { 'prod-2026': 'unknown', 'prod-2025': 'unknown' }
          : { 'prod-2026': i === 1 && ring === 1 ? 'not_enrolled' : 'enrolled', 'prod-2025': i === 1 && ring === 1 ? 'enrolled' : 'not_enrolled' },
        boot_target: { id: `demo-target-${id}`, kernel: i ? '7.0.0-42-generic' : '6.8.0-147-generic' } } };
    host.rollout_eligibility = { status: 'eligible', key_id: i === 1 && ring === 1 ? 'prod-2025' : 'prod-2026' };
    applyVersion(host, i ? 3 : ring === 1 ? 2 : 0);
    return host;
  }));
  if (scenario === 'mixed') {
    const offline = { ...structuredClone(hosts[0]), id: 'demo-offline', hostname: 'demo-offline', ring: 2, last_seen: ago(25) };
    Object.assign(offline.status, { firmware: 'unknown', secure_boot: 'unknown', lockdown: 'unknown', sig_enforce: 'unknown',
      boot_id: 'demo-boot-demo-offline', boot_target: { ...offline.status.boot_target, id: 'demo-target-demo-offline' },
      security_warning: 'lockdown·Secure Boot 상태를 읽지 못해 서명 필요로 판단',
      enrolled_certs: { 'prod-2026': 'unknown', 'prod-2025': 'unknown', 'retired-2024': 'enrolled' } });
    offline.rollout_eligibility.warning = '인증서 등록 상태를 확인하지 못해 active 사본 배포 (이전 에이전트 포함)';
    hosts.push(offline);
    Object.assign(hosts[3].status, { enrolled_certs: { 'prod-2026': 'not_enrolled', 'prod-2025': 'not_enrolled' } });
    hosts[3].rollout_eligibility = { status: 'blocked_mok_missing', reason: 'MOK 등록 필요' };
    const transition = structuredClone(hosts[2]);
    transition.id = 'demo-transition'; transition.hostname = 'demo-transition';
    transition.status.loaded[0].transition = true;
    transition.status.boot_id = 'demo-boot-demo-transition';
    transition.status.boot_target.id = 'demo-target-demo-transition';
    transition.status.enrolled_certs = { 'prod-2026': 'not_enrolled', 'prod-2025': 'not_enrolled' };
    transition.status.mok_pending = true;
    transition.rollout_eligibility = { status: 'blocked_mok_missing', reason: '다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요' };
    hosts.push(transition);
  }
  const patches = Object.fromEntries(kernels.map(kernel => [kernel, [1, 2, 3].map(n => ({
    id: `demo-${kernel}-p${n}`, kernel, state: 'active', source: 'manual', cves: [`CVE-2099-${1000 + n}`],
    title: `가상 보안 수정 ${n} — UI 개발용`, commit: `demo${n}`.padEnd(40, '0'),
    reason: '', content: `--- a/demo.c\n+++ b/demo.c\n@@ -1 +1 @@\n-unsafe_example();\n+checked_example_${n}();\n`,
  }))]));
  const jobs = [
    { id: 6, kernel: kernels[0], version: 3, status: 'built', patch_ids: patches[kernels[0]].map(p => p.id), new_patch_ids: [patches[kernels[0]][2].id], created_at: ago(10), requested_by: 'demo-builder' },
    { id: 5, kernel: kernels[1], version: 3, status: 'released', patch_ids: patches[kernels[1]].slice(0, 2).map(p => p.id), new_patch_ids: [], created_at: ago(3000), approved_at: ago(2900), approved_by: 'demo-admin', up_to_tag: 'Ubuntu-7.0.0-42.42' },
    { id: 4, kernel: kernels[0], version: 2, status: 'released', patch_ids: patches[kernels[0]].slice(0, 2).map(p => p.id), new_patch_ids: [], created_at: ago(3000), approved_at: ago(2900), approved_by: 'demo-admin', up_to_tag: 'Ubuntu-6.8.0-147.147' },
  ];
  for (const job of jobs) setDemoVMEvidence(job, job.id === 6 && scenario === 'mixed' ? 'failed' : 'passed');
  const prePatch = { id: `demo-${kernels[0]}-pre1`, kernel: kernels[0], prerelease: true, state: 'active', source: 'ubuntu',
    cves: ['CVE-2099-1004'], title: '출시 전 가상 CVE 수정 — 정식 APT 배포 전', commit: 'abcdef'.padEnd(40, '1'),
    content: '--- a/net/demo.c\n+++ b/net/demo.c\n@@ -1 +1 @@\n-before();\n+after();\n' };
  patches[kernels[0]].push(prePatch);
  jobs.unshift({ id: 7, kernel: kernels[0], version: -1, prerelease: true, prerelease_version: 1, status: 'built',
    patch_ids: patches[kernels[0]].map(patch => patch.id), new_patch_ids: [prePatch.id], created_at: ago(5), requested_by: 'demo-builder', module_name: moduleName(kernels[0], -1) });
  if (scenario === 'mixed') jobs.push({ id: 3, kernel: kernels[0], version: 1, status: 'failed', patch_ids: [], created_at: ago(100), error: '가상 빌드 실패 — 로그 확인 동작을 시험하세요.' });
  const signing = { mode: 'always', keys: [
    { id: 'prod-2026', active: true, expires_at: expires(365), enrolled_hosts: 0 },
    { id: 'prod-2025', active: false, expires_at: expires(scenario === 'mixed' ? 20 : 180), enrolled_hosts: 0,
      ...(scenario === 'mixed' && { warning: '인증서 만료가 30일 이내입니다' }) },
  ], warnings: scenario === 'mixed' ? ['demo-offline: 등록된 옛 키 retired-2024가 설정에서 빠졌습니다. 현재 키가 미등록이면 blocked_mok_missing으로 배포 제외됩니다'] : [] };
  const settings = { auto_enabled: false, auto_approve_only: false, auto_soak_minutes: 1440, min_soak_minutes: { 2: 1440 }, host_stale_minutes: 10, job_timeout_minutes: 180 };
  const status = { now: ago(), who: 'demo-admin', rings: [1, 2], host_stale_minutes: 10,
    auto: { enabled: false, paused: false, notes: {} }, hosts, jobs,
    tracks: kernels.map((kernel, i) => ({ kernel, ring_versions: { 1: kernelVersions[kernel], 2: i ? 3 : 0 }, ring_set_at: { 1: ago(2900), 2: ago(2900) }, prerelease_ring_versions: {}, prerelease_ring_set_at: {} })),
    latest_released: { ...kernelVersions }, released_tags: { [kernels[0]]: { 2: 'Ubuntu-6.8.0-147.147' }, [kernels[1]]: { 3: 'Ubuntu-7.0.0-42.42' } },
    unpatchable: [],
    upstream: Object.fromEntries(kernels.map((kernel, i) => [kernel, { latest_tag: i ? 'Ubuntu-7.0.0-42.42' : 'Ubuntu-6.8.0-147.147', collected_tag: i ? 'Ubuntu-7.0.0-42.42' : 'Ubuntu-6.8.0-147.147' }])),
    builders: { demo24: { name: 'demo-builder24', series: 'noble', addr: '192.0.2.24', last_seen: ago(), can_refresh: true, can_prerelease: true, up_to_date: true }, demo26: { name: 'demo-builder26', series: 'resolute', addr: '192.0.2.26', last_seen: ago(), can_refresh: true, can_prerelease: true, up_to_date: true } },
  };
  for (const [i, builder] of Object.values(status.builders).entries()) {
    builder.heartbeat_at = ago();
    builder.environment = 'isolated';
    builder.activity = { phase: i ? 'idle' : 'trial', kernel: kernels[i], started_at: ago(8),
      message: i ? '수집 주기 완료 · 다음 작업 대기' : '가상 CVE 시험 빌드',
      ...(!i && { cves: ['CVE-2099-1004'], commit: 'abcdef0123456789', current: 4, total: 12, step: '일회용 격리 환경 준비·컴파일' }) };
    builder.resources = { cpus: 10, jobs: 10, load1: i ? 0.3 : 8.5, memory_total: 16 * 1073741824,
      memory_available: 5 * 1073741824, disk_total: 150 * 1073741824, disk_available: 83 * 1073741824 };
  }
  if (scenario === 'empty') {
    status.hosts = []; status.jobs = []; status.tracks = []; status.builders = {}; status.latest_released = {}; status.released_tags = {}; status.upstream = {};
    for (const kernel of Object.keys(patches)) delete patches[kernel];
  }
  return { scenario, status, patches, signing, settings, fileSettings: structuredClone(settings), audit: [`${ago()}\tdemo\t가상 개발 환경 시작`] };
}

export function coverageData(host, params) {
  const states = ['included', 'pending', 'partial', 'vendor_fix_unknown', 'not_collected', 'disabled', 'unpatchable', 'base_fixed', 'outside_range', 'unknown'];
  const all = Array.from({ length: 145 }, (_, i) => ({ cve: `CVE-2099-${1000 + i}`, priority: i % 3 ? 'medium' : 'high', base_status: i % 10 > 6 ? states[i % 10] : 'affected',
    status: states[i % 10], vendor_fix_versions: i % 10 === 3 ? [] : [host.status.kernel.startsWith('6.8') ? '6.8.0-147.147' : '7.0.0-42.42'],
    patch_ids: [], details: ['개발용 가상 데이터입니다. 실제 CVE 보호·회귀 시험 결과가 아닙니다.'] }));
  const filter = params.get('state') || 'actionable', query = (params.get('q') || '').toLowerCase();
  const matching = all.filter(row => (filter === 'all' || filter === 'actionable' && !['base_fixed', 'outside_range', 'unknown'].includes(row.status) || row.status === filter) && row.cve.toLowerCase().includes(query));
  const offset = Math.max(0, Number(params.get('offset')) || 0);
  return { kernel: host.status.kernel, base_version: host.status.kernel_signature.split(' ')[1].replace('-generic', ''),
    inventory_count: all.length, fetched_at: ago(), source_stale: false, license: '개발용 가상 목록 — Canonical 공식 자료가 아닙니다.',
    counts: Object.fromEntries(states.map(state => [state, all.filter(row => row.status === state).length])),
    total: matching.length, offset, rows: matching.slice(offset, offset + 15) };
}
