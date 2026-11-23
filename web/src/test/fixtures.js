export function statusFixture(overrides = {}) {
  const now = new Date().toISOString();
  const vm = vmTestFixture();
  return { now, who: 'tester', rings: [1, 2], host_stale_minutes: 10,
    auto: { enabled: false, paused: false, notes: {} },
    tracks: [{ kernel: '6.8.0-136-generic', ring_versions: { 1: 2, 2: 0 } }],
    hosts: [{ id: 'host-1', hostname: 'canary', ring: 1, last_seen: now, cordoned: true, vm_count: 0, reboot_policy: 'drain',
      rollout_eligibility: { status: 'eligible', key_id: 'prod-2026' },
      status: { kernel: '6.8.0-136-generic', boot_id: 'boot-1', kernel_signature: 'Ubuntu 6.8.0-136.136-generic 6.8.12', version: 2, loaded: [{ name: 'kpctl_test', enabled: true, transition: false }],
        firmware: 'uefi', secure_boot: 'on', lockdown: 'integrity', sig_enforce: 'off', signature_required: true,
        security_warning: '', enrolled_certs: { 'prod-2026': 'enrolled', 'prod-2025': 'not_enrolled' }, mok_pending: false,
        boot_target: { id: 'prepared-target-hash', kernel: '6.8.0-147-generic' } } }],
    jobs: [{ id: 2, kernel: '6.8.0-136-generic', version: 2, status: 'released', patch_ids: ['p1'], created_at: now,
      module_name: 'kpctl_test', sha256: vm.sha256, active_signing_key: 'prod-2026', vm_test: vm,
      signing_artifacts: { 'prod-2026': { key_id: 'prod-2026', file: 'kpctl_test.ko', sha256: vm.sha256, signed: true, vm_test: structuredClone(vm) } } }],
    latest_released: { '6.8.0-136-generic': 2 }, unpatchable: [], builders: {}, ...overrides };
}
export function coverageFixture(overrides = {}) {
  return { kernel: '6.8.0-136-generic', base_version: '6.8.0-136.136', inventory_count: 17770,
    fetched_at: new Date().toISOString(), source_stale: false, license: 'CC-BY-SA-4.0',
    counts: { included: 1, not_collected: 1, unknown: 99 }, total: 2, offset: 0,
    rows: [{ cve: 'CVE-2026-43083', priority: 'high', base_status: 'affected', status: 'included', patch_ids: ['p1'], details: ['<img src=x onerror=alert(1)>'] },
      { cve: 'CVE-2026-43198', priority: 'high', base_status: 'affected', status: 'not_collected' }], ...overrides };
}
export function signingFixture(overrides = {}) {
  return { mode: 'always', keys: [
    { id: 'prod-2026', active: true, expires_at: new Date(Date.now() + 365 * 86400000).toISOString(), enrolled_hosts: 1 },
    { id: 'prod-2025', active: false, expires_at: new Date(Date.now() + 90 * 86400000).toISOString(), enrolled_hosts: 0 },
  ], warnings: [], ...overrides };
}
export function vmTestFixture(overrides = {}) {
  return { status: 'passed', sha256: '1'.repeat(64), modes: ['sb_on'], started_at: new Date().toISOString(), finished_at: new Date().toISOString(),
    steps: ['boot', 'negative_signature', 'load_previous', 'load_new', 'replace', 'smoke', 'rollback', 'cleanup', 'kernel_log'].map(name => ({
      name, status: 'passed', mode: 'sb_on', key_id: 'prod-2026', detail: `가상 ${name} 단계 결과`,
    })), ...overrides };
}
export function settingsFixture(overrides = {}) {
  const values = { auto_enabled: false, auto_approve_only: false, auto_soak_minutes: 1440, min_soak_minutes: { 2: 1440 }, host_stale_minutes: 10, job_timeout_minutes: 180 };
  return { current: structuredClone(values), file: structuredClone(values), rings: [1, 2], signing: signingFixture(), ...overrides };
}
export function response(data, status = 200, type = 'application/json') {
  return { ok: status >= 200 && status < 300, status, headers: { get: () => type }, text: async () => type === 'application/json' ? JSON.stringify(data) : String(data) };
}

export function builderFixture(overrides = {}) {
  const now = new Date().toISOString();
  return { name: 'builder24', series: 'noble', addr: '192.0.2.24', last_seen: now, heartbeat_at: now,
    can_refresh: true, can_prerelease: true, up_to_date: true, environment: 'isolated',
    activity: { phase: 'trial', kernel: '6.8.0-136-generic', cves: ['CVE-2099-1004'], commit: 'abcdef0123456789',
      current: 4, total: 12, started_at: now, message: '시험 중', step: '일회용 격리 환경 준비·컴파일' },
    resources: { cpus: 10, jobs: 10, load1: 7.2, memory_total: 16 * 1073741824, memory_available: 5 * 1073741824,
      disk_total: 150 * 1073741824, disk_available: 83 * 1073741824 }, ...overrides };
}
