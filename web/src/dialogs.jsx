import { useState } from 'react';
import { kernelPath } from './api.js';
import { useApp, useResource } from './store.jsx';
import { ver } from './selectors.js';
import { Button, DialogFrame, PatchDetails, Resource, TextDialog, useDialog, useMutation, VMTestEvidence } from './ui.jsx';

export function ReviewDialog({ job }) {
  const { status } = useApp();
  const { open } = useDialog();
  const resource = useResource(kernelPath(job.kernel) + '/patches');
  const action = useMutation();
  const first = status.rings[0];
  const [allowPrerelease, setAllowPrerelease] = useState(false);
  return <DialogFrame title={`작업 ${job.id} 검토`} busy={action.busy} actions={job.status === 'built' && <Button kind="primary" disabled={action.busy || resource.loading || Boolean(resource.error) || (job.prerelease && !allowPrerelease)} onClick={() => action.execute(api => api('POST', `/api/jobs/${job.id}/approve`, job.prerelease ? { prerelease: true } : undefined), `승인했습니다. 링 ${first} 에이전트가 다음 보고 때 적용합니다.`)}>승인 — 링 {first} 에 배포</Button>}>
    <p><span className="mono">{job.kernel}</span> <strong>{ver(job.version)}</strong></p>
    {job.prerelease && <div className="warning"><p>출시 전 후보입니다. VM 시험을 통과해야 배포할 수 있으며 자동 승인·승급과 즉시 업데이트는 사용할 수 없습니다.</p><label><input type="checkbox" checked={allowPrerelease} disabled={action.busy} onChange={event => setAllowPrerelease(event.target.checked)} />출시 전 작업의 VM 시험과 배포를 명시적으로 승인합니다</label></div>}
    <div className="warning">빌드 성공이 안전을 보장하지는 않습니다. 락 순서나 데이터 의미가 바뀌는 수정인지 diff를 확인하세요.</div>
    <VMTestEvidence result={job.vm_test} artifacts={job.signing_artifacts} activeKey={job.active_signing_key} label={`작업 ${job.id} VM 시험`} />
    <Resource resource={resource}>{patches => {
      const fresh = patches.filter(p => (job.new_patch_ids || []).includes(p.id));
      return <><p>새 패치 {fresh.length}건, 이전 패치 {Math.max(0, (job.patch_ids || []).length - fresh.length)}건 포함</p>{fresh.length ? fresh.map(p => <PatchDetails key={p.id} patch={p} />) : <p className="muted">새 패치가 없는 재빌드입니다.</p>}</>;
    }}</Resource>
    <Button disabled={action.busy} onClick={() => open(<TextDialog title={`작업 ${job.id} 빌드 로그`} path={`/api/jobs/${job.id}/log`} />)}>빌드 로그 보기</Button>
    {action.error && <p className="error" role="alert">{action.error}</p>}
  </DialogFrame>;
}
export function PromoteDialog({ kernel, ring, version }) {
  const { refresh } = useApp();
  const action = useMutation();
  const [blocked, setBlocked] = useState(false);
  const [stale, setStale] = useState(false);
  const submit = force => action.execute(async api => {
    const result = await api('POST', kernelPath(kernel) + '/promote', { ring, force, expected_version: version, ...(version < 0 ? { prerelease: true } : {}) });
    const excluded = result?.excluded_hosts || [];
    const count = Math.max(result?.excluded_count || 0, excluded.length);
    const reasons = excluded.map(host => `${host.hostname || host.id}: ${host.reason}`).join(' · ');
    return { ...result, message: `링 ${ring}에 ${ver(result?.version ?? version)} 배포를 시작했습니다.${count ? ` 배포 제외 ${count}대${reasons ? ' — ' + reasons : ''}` : ''}` };
  }, undefined, err => {
    if (err.status === 412) {
      setBlocked(false);
      setStale(true);
      void refresh();
    } else if (err.status === 409) {
      setBlocked(true);
    }
  });
  return <DialogFrame title={`링 ${ring} 승급`} busy={action.busy} actions={<>
    <Button kind="primary" disabled={action.busy || stale} onClick={() => submit(false)}>{blocked ? '다시 검사 후 승급' : '승급'}</Button>
    {blocked && <Button kind="danger-solid" disabled={action.busy} onClick={() => submit(true)}>검사를 무시하고 승급</Button>}
  </>}>
    <p><span className="mono">{kernel}</span> {ver(version)}를 링 {ring}에 배포합니다.</p>
    {action.error && <div role="alert" className="danger-note">{action.error}</div>}
    {blocked && <p className="warning">강제 승급은 호스트 건강·적용 상태·관찰 시간 검사를 건너뜁니다. 원인을 확인한 뒤 결정하세요.</p>}
  </DialogFrame>;
}
export function RollbackDialog({ track }) {
  const { status } = useApp();
  const versions = [...new Set(status.jobs.filter(j => j.kernel === track.kernel && j.status === 'released').map(j => j.version))];
  const [version, setVersion] = useState(String(versions[0] || 0));
  const action = useMutation();
  return <DialogFrame title="롤백" busy={action.busy} actions={<Button kind="danger-solid" disabled={action.busy} onClick={() => action.execute(api => api('POST', kernelPath(track.kernel) + '/rollback', { version: Number(version), ...(Number(version) < 0 ? { prerelease: true } : {}) }), '모든 링에 되돌리도록 지시했습니다.')}>롤백 실행</Button>}>
    <p><span className="mono">{track.kernel}</span>의 <strong>모든 링</strong>을 선택한 버전으로 되돌립니다.</p>
    <label htmlFor="rollback-version">되돌릴 버전</label><select id="rollback-version" value={version} disabled={action.busy} onChange={event => setVersion(event.target.value)}>{versions.map(v => <option key={v} value={v}>{ver(v)}</option>)}<option value="0">0 — 패치 전부 내림</option></select>
    <div className="warning">자동 배포는 직접 재개할 때까지 멈춥니다. 문제 패치는 패치 화면에서 끄세요. v0는 라이브패치를 모두 내려 보호를 해제합니다.</div>
    {action.error && <p className="error" role="alert">{action.error}</p>}
  </DialogFrame>;
}
