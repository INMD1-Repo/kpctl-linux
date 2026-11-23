import { useState } from 'react';
import { useApp, usePolling, useResource } from './store.jsx';
import { ago, isSet, ver } from './selectors.js';
import { Badge, Button, DialogFrame, LiveLog, Resource, useDialog } from './ui.jsx';

const PHASES = {
  idle: ['대기', 'ok'], discovering: ['CVE 수집', 'warn'], trial: ['CVE 시험 빌드', 'warn'],
  building: ['누적 빌드', 'warn'], failed: ['오류 · 로그 확인', 'bad'], stopped: ['종료됨', ''],
};
const gib = bytes => Number.isFinite(bytes) ? (bytes / 1073741824).toFixed(1) + ' GiB' : '-';

function health(builder, now) {
  if (builder.activity?.phase === 'stopped') return ['종료됨', 'warn'];
  if (isSet(builder.heartbeat_at)) return new Date(now) - new Date(builder.heartbeat_at) > 30000
    ? ['상태 보고 지연', 'bad'] : ['연결됨', 'ok'];
  return new Date(now) - new Date(builder.last_seen) > 300000
    ? ['최근 연결 없음', 'warn'] : ['실시간 보고 미지원', 'warn'];
}

function BuilderStatus({ builder, now }) {
  const a = builder.activity;
  const r = builder.resources;
  const cache = builder.cache;
  return <>
    <div className="actions builder-state">
      <Badge value={health(builder, now)} />
      {a && <Badge value={PHASES[a.phase] || [a.phase, '']} />}
      <Badge value={builder.up_to_date ? ['최신 빌더', 'ok'] : ['빌더 업데이트 대기', 'warn']} />
    </div>
    {a ? <div className="builder-activity">
      {a.kernel && <div className="mono wrap">{a.kernel}{a.job_id > 0 && ` · 작업 ${a.job_id} ${ver(a.version)}`}</div>}
      {a.cves?.length > 0 && <div className="mono wrap">{a.cves.join(', ')}{a.commit && ` · ${a.commit.slice(0, 12)}`}</div>}
      {a.current > 0 && <div>이번 수집의 시험 대상 {a.current} / {a.total}</div>}
      <div className={a.phase === 'failed' ? 'error wrap' : 'wrap'}>{a.message}</div>
      {a.step && <strong className="wrap">{a.step}</strong>}
      {isSet(a.started_at) && a.phase !== 'idle' && <div className="muted small-note">시작 {ago(a.started_at, now)}</div>}
    </div> : <p className="hint">빌더가 업데이트되면 진행 단계와 실행 로그를 보고합니다.</p>}
    {r && <dl className="builder-metrics">
      <div><dt>CPU · 병렬 빌드</dt><dd>{r.cpus}개 · {r.jobs || '자동'}</dd></div>
      <div><dt>서버 부하 (1분)</dt><dd>{Number(r.load1).toFixed(2)}</dd></div>
      <div><dt>서버 메모리 여유</dt><dd>{gib(r.memory_available)} / {gib(r.memory_total)}</dd></div>
      <div><dt>디스크 여유</dt><dd>{gib(r.disk_available)} / {gib(r.disk_total)}</dd></div>
    </dl>}
    {r?.disk_minimum > 0 && r.disk_available <= r.disk_minimum + 20 * 1073741824 && <p role="status"><Badge value={['디스크 여유 확인', 'warn']} /> 빌드 시작 기준 {gib(r.disk_minimum)} + 예방 여유 20 GiB 이하입니다.</p>}
    {builder.maintenance && <p className="muted small-note wrap">최근 환경 정리 · {builder.maintenance}</p>}
    {cache && <div className="builder-cache">
      <div>최근 빌드 ccache · {cache.enabled ? `${cache.hit_rate == null ? '측정 불가' : (cache.hit_rate * 100).toFixed(1) + '% 적중'} · hit ${cache.hits} / miss ${cache.misses}` : '캐시 비활성'}</div>
      <div className="muted small-note">{cache.kernel} · 빌드 {Math.round(cache.build_seconds || 0)}초{cache.baseline_seconds > 0 && ` · 기준 빌드 ${Math.round(cache.baseline_seconds)}초`}</div>
      {cache.warning && <p role="status"><Badge value={['캐시 성능 확인', 'warn']} /> {cache.warning}</p>}
    </div>}
    <div className="muted small-note">
      {builder.environment === 'isolated' ? '일회용 격리 환경' : builder.environment === 'host' ? '호스트 빌드 환경' : '환경 정보 대기'}
      {' · '}{builder.series || '시리즈 미지정'} · {builder.addr || '주소 대기'}
    </div>
    <div className="muted small-note">마지막 상태 보고 {ago(isSet(builder.heartbeat_at) ? builder.heartbeat_at : builder.last_seen, now)}</div>
  </>;
}

export function BuilderLogDialog({ name }) {
  const [following, setFollowing] = useState(true);
  const { revision, reload } = usePolling(5000, following);
  const resource = useResource('/api/builders/' + encodeURIComponent(name), revision);
  return <DialogFrame title={`${name} 상태·실시간 로그`}>
    <div className="actions log-controls">
      <span className="muted">{following ? '5초마다 갱신 · 최신 로그 따라가기' : '자동 갱신 일시 중지'}</span>
      <Button onClick={() => setFollowing(value => !value)}>{following ? '자동 갱신 중지' : '자동 갱신 재개'}</Button>
      <Button onClick={reload}>새로고침</Button>
    </div>
    <Resource resource={resource}>{data => <>
      <BuilderStatus builder={data.builder} now={new Date().toISOString()} />
      <p className="hint">수집·환경 준비·시험·누적 빌드의 최근 실행 로그입니다. 완료된 작업의 전체 결과 로그는 빌드 작업에서 확인할 수 있습니다.</p>
      {data.builder.log_truncated && <p className="hint">로그가 길어 최근 256 KiB를 표시합니다.</p>}
      <LiveLog text={data.log} following={following} />
    </>}</Resource>
  </DialogFrame>;
}

export default function Builders() {
  const { status } = useApp();
  const { open } = useDialog();
  const builders = Object.values(status.builders || {}).sort((a, b) => a.name.localeCompare(b.name));
  if (!builders.length) return null;
  return <section className="builders">
    <h2>빌드 서버 상태·로그</h2>
    <div className="builder-grid">{builders.map(builder => <article className="builder-card" key={builder.name}>
      <header><h3>{builder.name}</h3><Button onClick={() => open(<BuilderLogDialog name={builder.name} />)}>실시간 상태·로그</Button></header>
      <BuilderStatus builder={builder} now={status.now} />
    </article>)}</div>
  </section>;
}
