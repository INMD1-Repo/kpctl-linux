import { ago, applyVersion, coverageData, DEMO_TOKEN, initialData, SCENARIOS, setDemoVMEvidence } from './data.js';

const ok = (body, type = 'application/json') => ({ status: 200, body, type });
const fail = (status, error) => ({ status, body: { error }, type: 'application/json' });
export function createDemoStore({ testVMEnabled = true, signingMode = 'always' } = {}) {
  let data = initialData();
  data.signing.mode = signingMode;
  const record = text => data.audit.push(`${ago()}\tdemo-admin\t${text}`);
  const signing = () => {
    const result = structuredClone(data.signing);
    for (const key of result.keys) key.enrolled_hosts = data.status.hosts.filter(host => host.status.enrolled_certs?.[key.id] === 'enrolled').length;
    const configured = new Set(result.keys.map(key => key.id));
    result.warnings = data.status.hosts.flatMap(host => {
      const enrolled = Object.entries(host.status.enrolled_certs || {}).filter(([, state]) => state === 'enrolled').map(([id]) => id);
      const removed = enrolled.filter(id => !configured.has(id));
      return removed.length && !enrolled.some(id => configured.has(id))
        ? [`${host.hostname}: 등록된 옛 키 ${removed.sort().join(', ')}가 설정에서 빠졌습니다. 현재 키가 미등록이면 blocked_mok_missing으로 배포 제외됩니다`] : [];
    });
    return result;
  };
  const settings = () => ({ current: structuredClone(data.settings), file: structuredClone(data.fileSettings), rings: [1, 2], signing: signing() });
  const target = (track, ring) => track?.prerelease_ring_versions?.[ring] || track?.ring_versions?.[ring] || 0;
  const hasPrerelease = track => Object.values(track?.prerelease_ring_versions || {}).some(version => version !== 0);
  const setTarget = (track, ring, version) => {
    if (version < 0) {
      track.prerelease_ring_versions[ring] = version; track.prerelease_ring_set_at[ring] = ago();
    } else {
      track.ring_versions[ring] = version; track.ring_set_at[ring] = ago();
      delete track.prerelease_ring_versions[ring]; delete track.prerelease_ring_set_at[ring];
    }
  };
  const released = (kernel, version) => data.status.jobs.find(job => job.kernel === kernel && job.version === version && job.status === 'released');
  const officialPatches = kernel => (data.patches[kernel] || []).filter(patch => !patch.prerelease && patch.state === 'active');
  function eligibility(host, job) {
    const status = host.status;
    const missing = [['secure_boot', ['on', 'off']], ['lockdown', ['none', 'integrity', 'confidentiality']], ['sig_enforce', ['on', 'off']]]
      .filter(([name, values]) => !values.includes(status[name])).map(([name]) => name);
    status.signature_required = Boolean(status.signature_required || missing.length || status.secure_boot === 'on' || ['integrity', 'confidentiality'].includes(status.lockdown) || status.sig_enforce === 'on');
    if (missing.length && !status.security_warning?.includes('서명 필요로 판단')) status.security_warning = [status.security_warning, `${missing.join(', ')} 상태를 읽지 못해 서명 필요로 판단`].filter(Boolean).join('; ');
    const active = data.signing.keys.find(key => key.active)?.id || '';
    const result = { status: 'eligible', key_id: active, warning: status.security_warning || '' };
    if (!status.signature_required) return { ...result, key_id: job?.active_signing_key || active };
    if (data.signing.mode === 'never') return { ...result, status: 'blocked_signing_disabled', reason: '서명이 필요한 호스트: signing.mode=never로 배포 제외', warning: '서명이 필요한 호스트: signing.mode=never로 배포 제외' };
    const candidates = [active, ...data.signing.keys.filter(key => key.id !== active).map(key => key.id)];
    let unknown = !data.signing.keys.length, missingArtifact = false;
    for (const id of candidates) {
      const enrolled = status.enrolled_certs?.[id];
      if (enrolled === 'enrolled') {
        if (job?.signing_artifacts && Object.keys(job.signing_artifacts).length && !job.signing_artifacts[id]?.signed) { missingArtifact = true; continue; }
        return { ...result, key_id: id };
      }
      if (enrolled !== 'not_enrolled') unknown = true;
    }
    if (missingArtifact) return { ...result, status: 'blocked_artifact', reason: '등록된 키의 서명 사본이 없어 새 누적 빌드·승인 필요' };
    if (unknown) {
      if (job?.signing_artifacts && Object.keys(job.signing_artifacts).length && !job.signing_artifacts[active]?.signed) return { ...result, status: 'blocked_artifact', reason: 'active 키의 서명 사본이 없어 새 누적 빌드·승인 필요' };
      return { ...result, warning: [result.warning, '인증서 등록 상태를 확인하지 못해 active 사본 배포 (이전 에이전트 포함)'].filter(Boolean).join('; ') };
    }
    return { ...result, status: 'blocked_mok_missing', key_id: '', reason: status.mok_pending ? '다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요' : 'MOK 등록 필요' };
  }
  const excluded = kernel => data.status.hosts.filter(host => host.status.kernel === kernel).flatMap(host => {
    const track = data.status.tracks.find(item => item.kernel === kernel);
    const result = eligibility(host, released(kernel, target(track, host.ring)));
    return result.status === 'eligible' ? [] : [{ id: host.id, hostname: host.hostname, reason: result.reason }];
  });
  function advance() {
    const s = data.status;
    s.now = ago(); s.host_stale_minutes = data.settings.host_stale_minutes;
    for (const builder of Object.values(s.builders)) builder.heartbeat_at = builder.last_seen = ago();
    s.auto.enabled = data.settings.auto_enabled; s.auto.approve_only = data.settings.auto_approve_only; s.auto.soak_minutes = data.settings.auto_soak_minutes;
    s.auto.notes = {};
    for (const track of s.tracks) {
      if (hasPrerelease(track)) s.auto.notes[track.kernel] = ['출시 전 누적본 배포 중: 자동 승인·승급 보류, 관리자의 명시적 조작 필요'];
      else if (track.auto_hold) s.auto.notes[track.kernel] = ['자동 배포 멈춤: ' + track.auto_hold];
      else if (s.jobs.some(job => job.kernel === track.kernel && job.prerelease && job.status === 'built')) s.auto.notes[track.kernel] = ['출시 전 작업은 관리자의 명시적 승인과 VM 시험 필요'];
    }
    for (const host of s.hosts) {
      const track = s.tracks.find(item => item.kernel === host.status.kernel);
      let version = target(track, host.ring);
      if (version >= 0 && host.update_now_kernel === host.status.kernel) version = Math.max(version, host.update_now_version || 0);
      host.rollout_eligibility = eligibility(host, released(host.status.kernel, version));
      if (host.id === 'demo-offline' || host.id === 'demo-transition') continue;
      host.last_seen = ago();
      // 배포 제외는 현재 보호를 유지합니다. 명시적 v0 롤백만 기존 모듈을 내립니다.
      if (version === 0 || host.rollout_eligibility.status === 'eligible') applyVersion(host, version);
    }
  }
  function prereleaseApprovalProblem(job, allowed) {
    if (!job.prerelease) return '';
    if (allowed !== true) return '출시 전 작업은 prerelease 플래그로 명시적으로 승인해야 합니다.';
    if (!testVMEnabled) return '출시 전 작업은 test_vm.enabled=true 환경에서 VM 시험을 거쳐야 합니다.';
    if (job.version >= 0 || job.prerelease_version !== -job.version) return '출시 전 전용 버전 번호가 잘못됐습니다.';
    if (officialPatches(job.kernel).some(patch => !job.patch_ids.includes(patch.id))) return '출시 전 작업의 정식 누적 입력이 오래됐습니다. 다시 빌드하세요.';
    return '';
  }
  function handle(method, path, body = {}, token = '') {
    if (token !== DEMO_TOKEN) return fail(401, `개발 환경 토큰은 ${DEMO_TOKEN}입니다.`);
    const url = new URL(path, 'http://demo.invalid');
    const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
    if (method === 'GET' && url.pathname === '/api/dev/info') return ok({ scenario: data.scenario });
    if (method === 'POST' && url.pathname === '/api/dev/reset') {
      if (!SCENARIOS.includes(body.scenario || 'mixed')) return fail(400, '알 수 없는 가상 시나리오');
      data = initialData(body.scenario || 'mixed');
      data.signing.mode = signingMode;
      return ok({ message: '가상 데이터를 초기화했습니다.' });
    }
    const s = data.status;
    if (method === 'GET' && url.pathname === '/api/signing') return ok(signing());
    if (method === 'GET' && url.pathname === '/api/status') {
      advance();
      return ok(structuredClone(s));
    }
    if (method === 'GET' && parts[1] === 'builders' && parts.length === 3) {
      const builder = Object.values(s.builders).find(b => b.name === parts[2]);
      if (!builder) return fail(404, '가상 빌드 서버가 없습니다.');
      builder.heartbeat_at = builder.last_seen = ago();
      return ok({ builder: structuredClone(builder), log: `가상 빌드 서버 로그 · ${ago()}\n${builder.name}\n${builder.activity.message}\n${builder.activity.step || '작업 대기'}\n실제 컴파일이나 운영 서버 연결은 없습니다.` });
    }
    if (url.pathname === '/api/settings') {
      if (method === 'GET') return ok(settings());
      if (method === 'POST') {
        const editable = ['auto_enabled', 'auto_approve_only', 'auto_soak_minutes', 'min_soak_minutes', 'host_stale_minutes', 'job_timeout_minutes'];
        if (Object.keys(body).some(key => !editable.includes(key))) return fail(400, '설정에 알 수 없거나 읽기 전용인 필드가 있습니다.');
        for (const [key, min] of [['auto_soak_minutes', 0], ['host_stale_minutes', 1], ['job_timeout_minutes', 10]]) {
          if (!Number.isSafeInteger(body[key]) || body[key] < min) return fail(400, `${key}: ${min} 이상의 정수가 필요합니다.`);
        }
        if (typeof body.auto_enabled !== 'boolean' || typeof body.auto_approve_only !== 'boolean' || Object.entries(body.min_soak_minutes || {}).some(([ring, n]) => !s.rings.includes(Number(ring)) || !Number.isSafeInteger(n) || n < 0)) return fail(400, '설정 형식이 잘못됐습니다.');
        data.settings = structuredClone(body); record('설정 저장'); return ok(settings());
      }
    }
    if (method === 'GET' && url.pathname === '/api/coverage') {
      if (data.scenario === 'source-error') return fail(503, '가상 시나리오: 공식 목록 조회 실패');
      const host = s.hosts.find(h => h.id === url.searchParams.get('host'));
      return host ? ok(coverageData(host, url.searchParams)) : fail(404, '가상 호스트가 없습니다.');
    }
    if (method === 'GET' && url.pathname === '/api/audit') return ok(data.audit.slice(-500).join('\n'), 'text/plain');
    if (parts[1] === 'patches') {
      const patch = Object.values(data.patches).flat().find(p => p.id === parts[2]);
      if (!patch) return fail(404, '가상 패치가 없습니다.');
      if (method === 'GET' && parts[3] === 'diff') return ok(patch.content, 'text/plain');
      if (method === 'POST' && parts[3] === 'state' && ['active', 'disabled'].includes(body.state)) { patch.state = body.state; record(`패치 ${patch.id}: ${body.state}`); return ok({ message: '가상 패치 상태 변경' }); }
    }
    if (parts[1] === 'jobs') {
      const job = s.jobs.find(j => j.id === Number(parts[2]));
      if (!job) return fail(404, '가상 작업이 없습니다.');
      if (method === 'GET' && parts[3] === 'log') return ok(`가상 빌드 로그\njob ${job.id}: ${job.status}\n${job.error || '가상 모듈 생성·검증 완료 (실제 컴파일 아님)'}`, 'text/plain');
      if (method === 'POST' && parts[3] === 'approve') {
        if (job.status !== 'built') return fail(409, '가상 작업이 승인 대기 상태가 아닙니다.');
        const problem = prereleaseApprovalProblem(job, body.prerelease);
        if (problem) return fail(409, problem);
        if (testVMEnabled && data.signing.mode === 'never') return fail(409, '서명 강제가 필요한 가상 VM 모드에서 signing.mode=never로 승인할 수 없습니다.');
        setDemoVMEvidence(job); job.status = 'released'; job.approved_at = job.released_at = ago(); job.approved_by = 'demo-admin';
        if (!testVMEnabled) {
          delete job.vm_test;
          for (const artifact of Object.values(job.signing_artifacts)) { delete artifact.vm_test; artifact.signed = data.signing.mode !== 'never'; }
        }
        setTarget(s.tracks.find(t => t.kernel === job.kernel), s.rings[0], job.version);
        if (!job.prerelease) s.latest_released[job.kernel] = job.version;
        record(`작업 ${job.id} 가상 승인${job.prerelease ? ' · 출시 전 명시 승인' : ''}`);
        return ok({ result: 'released', kernel: job.kernel, version: job.version, ring: s.rings[0], message: '가상 카나리 배포 완료' });
      }
    }
    if (parts[1] === 'hosts') {
      const host = s.hosts.find(h => h.id === parts[2]);
      if (!host) return fail(404, '가상 호스트가 없습니다.');
      if (method === 'DELETE' && !parts[3]) { s.hosts = s.hosts.filter(h => h !== host); record(`${host.hostname} 가상 등록 삭제`); return ok({ message: '가상 등록 삭제 완료' }); }
      if (method === 'POST') {
        if (!parts[3] && s.rings.includes(body.ring)) host.ring = body.ring;
        else if (parts[3] === 'cordon') host.cordoned = Boolean(body.on);
        else if (parts[3] === 'update-now') {
          if (!body.cancel && body.version < 0) return fail(400, '출시 전 버전은 즉시 업데이트로 적용할 수 없습니다.');
          const track = s.tracks.find(item => item.kernel === host.status.kernel);
          if (!body.cancel && track?.prerelease_ring_versions?.[host.ring]) return fail(409, '이 호스트는 출시 전 누적본 배포 중입니다. 정식 승인·승급 또는 명시적 롤백으로 전환하세요.');
          if (!body.cancel && body.kernel && body.kernel !== host.status.kernel) return fail(409, '호스트 커널이 바뀌었습니다.');
          const version = s.latest_released[host.status.kernel] || 0;
          if (!body.cancel && body.version && body.version !== version) return fail(409, '최신 승인 버전이 바뀌었습니다.');
          if (!body.cancel && (!version || version < host.status.version)) return fail(409, '적용할 최신 승인 버전이 없습니다.');
          host.update_now_kernel = host.status.kernel; host.update_now_version = body.cancel ? 0 : version;
        }
        else if (parts[3] === 'prepare-kernel') {
          if (body.cancel) host.kernel_prepare_request = null;
          else {
            if (host.status.boot_target || host.reboot_policy !== 'drain' || (body.kernel && body.kernel !== host.status.kernel)) return fail(409, '가상 커널 준비 조건이 다릅니다.');
            host.kernel_prepare_request = { kernel: host.status.kernel, requested_by: 'demo-admin', requested_at: ago() };
          }
        }
        else if (parts[3] === 'reboot') {
          if (body.cancel) host.reboot_approval = null;
          else {
            if (host.reboot_approval || !host.cordoned || host.vm_count !== 0 || host.reboot_policy !== 'drain' || body.target_id !== host.status.boot_target?.id) return fail(409, '가상 재부팅 조건 또는 대상이 다릅니다.');
            host.reboot_approval = { id: `demo-approval-${host.id}`, approved_at: ago(), expires_at: ago(-5), dispatched_at: '0001-01-01T00:00:00Z' };
          }
        } else return fail(400, '지원하지 않는 가상 호스트 변경');
        record(`${host.hostname}: ${parts[3] || '링 변경'}`); return ok({ message: '가상 호스트 상태 변경 — 실제 서버 작업 없음' });
      }
    }
    if (method === 'POST' && url.pathname === '/api/auto') { s.auto.paused = Boolean(body.paused); s.auto.paused_by = 'demo-admin'; record('자동 배포 가상 일시 중지 변경'); return ok({ message: '가상 자동 배포 상태 변경' }); }
    if (parts[1] === 'kernels') {
      const kernel = parts[2], track = s.tracks.find(t => t.kernel === kernel);
      if (!track) return fail(404, '가상 커널이 없습니다.');
      if (method === 'GET' && parts[3] === 'patches') return ok(structuredClone(data.patches[kernel] || []));
      if (method === 'POST') {
        if (parts[3] === 'auto') track.auto_hold = body.hold ? '개발 환경에서 일시 중지' : '';
        else if (parts[3] === 'promote') {
          const index = s.rings.indexOf(body.ring), previous = s.rings[index - 1];
          const version = target(track, previous);
          if (index < 1) return fail(400, '가상 승급 대상 링을 확인하세요.');
          if (body.expected_version != null && !Number.isSafeInteger(body.expected_version)) return fail(400, '가상 승급 예상 버전은 정수여야 합니다.');
          if (body.expected_version != null && body.expected_version !== version) return fail(412, '이전 링의 가상 목표 버전이 바뀌었습니다. 현재 버전을 확인하고 다시 승급하세요.');
          if (!version) return fail(409, '이전 링에 배포한 가상 버전이 없습니다.');
          const approved = released(kernel, version);
          if (version < 0) {
            const problem = !approved?.prerelease ? '출시 전 배포 작업을 확인하지 못했습니다.' : prereleaseApprovalProblem(approved, body.prerelease);
            if (problem) return fail(409, problem);
          }
          if (target(track, body.ring) === version) return fail(409, '해당 링은 이미 같은 버전입니다.');
          const previousHosts = s.hosts.filter(host => host.status.kernel === kernel && host.ring === previous);
          const eligible = previousHosts.filter(host => eligibility(host, approved).status === 'eligible');
          const setAt = version < 0 ? track.prerelease_ring_set_at[previous] : track.ring_set_at[previous];
          const unhealthy = eligible.some(host => Date.now() - new Date(host.last_seen) > data.settings.host_stale_minutes * 60000 || host.status.error || host.status.version !== version || host.status.loaded.some(module => module.transition) || !host.status.loaded.some(module => module.name === approved?.module_name && module.enabled && !module.transition));
          if (!body.force && (!previousHosts.length || Date.now() - new Date(setAt || approved?.approved_at || ago()) < (data.settings.min_soak_minutes[body.ring] || 0) * 60000 || unhealthy)) return fail(409, '가상 승급 검사 실패: 관찰 시간 또는 호스트 상태를 확인하세요.');
          setTarget(track, body.ring, version);
          const excludedHosts = excluded(kernel);
          record(`${kernel}: 가상 승급`);
          return ok({ result: 'ok', ring: body.ring, version, excluded_count: excludedHosts.length, excluded_hosts: excludedHosts, message: '가상 승급 완료' });
        } else if (parts[3] === 'rollback') {
          if (!Number.isSafeInteger(body.version)) return fail(400, '가상 롤백 버전은 정수여야 합니다.');
          if (body.version !== 0 && !s.jobs.some(j => j.kernel === kernel && j.status === 'released' && j.version === body.version)) return fail(400, '배포한 가상 버전을 선택하세요.');
          if (body.version < 0 && body.prerelease !== true) return fail(409, '출시 전 롤백은 prerelease 플래그를 명시해야 합니다.');
          for (const ring of s.rings) setTarget(track, ring, body.version);
          for (const host of s.hosts.filter(h => h.status.kernel === kernel)) { host.update_now_version = 0; host.update_now_kernel = ''; }
          track.auto_hold = '가상 롤백 후 검토 대기';
        } else if (parts[3] === 'purge') {
          s.upstream = s.upstream || {};
          const u = s.upstream[kernel] = s.upstream[kernel] || {};
          if (!body?.cancel && !u.outside) return fail(409, '최근 커널 범위 안이라 지울 수 없습니다.');
          u.purge_requested_at = body?.cancel ? '' : ago();
                } else if (['build', 'refresh'].includes(parts[3])) {
          const formalCommits = new Set(data.patches[kernel].filter(patch => !patch.prerelease).map(patch => patch.commit));
          const active = data.patches[kernel].filter(patch => patch.state === 'active' && (!patch.prerelease || body.prerelease === true && !formalCommits.has(patch.commit))).map(patch => patch.id);
          const id = Math.max(0, ...s.jobs.map(j => j.id)) + 1;
          const prerelease = body.prerelease === true;
          const sequence = Math.max(0, ...s.jobs.filter(job => job.kernel === kernel && Boolean(job.prerelease) === prerelease).map(job => prerelease ? job.prerelease_version : job.version)) + 1;
          for (const job of s.jobs) if (job.kernel === kernel && Boolean(job.prerelease) === prerelease && job.status === 'built') job.status = 'superseded';
          s.jobs.unshift({ id, kernel, version: prerelease ? -sequence : sequence, ...(prerelease && { prerelease: true, prerelease_version: sequence }),
            status: 'built', patch_ids: active, new_patch_ids: active, created_at: ago(), requested_by: 'demo-admin' });
        } else return fail(404, '가상 API 경로가 없습니다.');
        record(`${kernel}: ${parts[3]}`); return ok({ message: '가상 요청 완료 — 실제 빌드·배포·재부팅 없음' });
      }
    }
    return fail(404, '가상 API 경로가 없습니다. 운영 API로 전달하지 않습니다.');
  }
  return { handle };
}
