import { kernelPath } from "../api.js";
import Builders from "../Builders.jsx";
import CollectionProblem from "../CollectionProblem.jsx";
import { ReviewDialog, PromoteDialog, RollbackDialog } from "../dialogs.jsx";
import { useApp } from "../store.jsx";
import { ago, cmpVer, hostState, isHWE, ver, trackTarget } from "../selectors.js";
import {
  Badge,
  Button,
  Confirm,
  Empty,
  MutationButton,
  TextDialog,
  useDialog,
  ValidationBanner,
} from "../ui.jsx";

function AutoBanner({ navigate }) {
  const { status } = useApp();
  const { open } = useDialog();
  const auto = status.auto;
  if (!auto?.enabled)
    return (
      <div className="auto off">
        <strong>자동 배포 꺼짐</strong>
        <span className="muted">승인과 승급을 사람이 직접 합니다.</span>
        <Button onClick={() => navigate("settings")}>설정에서 켜기</Button>
      </div>
    );
  if (auto.paused)
    return (
      <div className="auto paused">
        <strong>자동 배포 일시 중지</strong>
        <span>
          {auto.paused_by}가 멈췄습니다. 재개 전까지 자동으로 배포되지 않습니다.
        </span>
        <MutationButton
          path="/api/auto"
          body={{ paused: false }}
          message="자동 배포를 재개했습니다."
          kind="primary"
        >
          재개
        </MutationButton>
      </div>
    );
  return (
    <div className="auto on">
      <strong>자동 배포 켜짐</strong>
      <span className="muted">
        {auto.approve_only
          ? "새 빌드를 첫 번째 링까지 자동 배포합니다. 다음 링은 직접 승급합니다."
          : `새 빌드를 자동 승인하고, 링마다 ${auto.soak_minutes}분 관찰 뒤 다음 링으로 넘깁니다.`}
      </span>
      <Button
        onClick={() =>
          open(
            <Confirm
              title="자동 배포 일시 중지"
              label="일시 중지"
              onConfirm={(api) => api("POST", "/api/auto", { paused: true })}
              message="자동 배포를 멈췄습니다."
            >
              모든 커널의 자동 승인과 승급을 멈춥니다. 이미 배포된 패치는 그대로
              유지됩니다.
            </Confirm>,
          )
        }
      >
        전체 일시 중지
      </Button>
    </div>
  );
}
// 호스트가 쓰고 있는 커널을 최신순으로 먼저 보이고, 호스트가 없는 이전 커널은
// 맨 아래 접힌 칸으로 보내 지금 배포 중인 커널과 헷갈리지 않게 합니다.
function KernelCards() {
  const { status } = useApp();
  const used = new Set(
    status.hosts.filter((h) => !isHWE(h)).map((h) => h.status.kernel),
  );
  const sorted = [...status.tracks].sort((a, b) => cmpVer(b.kernel, a.kernel));
  const current = sorted.filter((t) => used.has(t.kernel));
  const old = sorted.filter((t) => !used.has(t.kernel));
  return (
    <>
      {current.length ? (
        current.map((track) => <KernelCard key={track.kernel} track={track} />)
      ) : (
        <Empty>지금 이 커널을 쓰는 호스트가 없습니다.</Empty>
      )}
      {old.length > 0 && (
        <details className="old-kernels">
          <summary>
            이전 커널 {old.length}개 (사용 중인 호스트 없음)
          </summary>
          {old.map((track) => (
            <KernelCard key={track.kernel} track={track} />
          ))}
        </details>
      )}
    </>
  );
}
function KernelCard({ track }) {
  const { status } = useApp();
  const { open } = useDialog();
  const hosts = status.hosts.filter(
    (h) => h.status.kernel === track.kernel && !isHWE(h),
  );
  const notes = status.auto?.notes?.[track.kernel] || [];
  const adminExcluded = status.upstream?.[track.kernel]?.problem_resolution === "admin_exclusion";
  const nextIndex = status.rings.findIndex(
    (ring, i) =>
      i > 0 &&
      (trackTarget(track, status.rings[i - 1]) < 0
        ? trackTarget(track, status.rings[i - 1]) !== trackTarget(track, ring)
        : (trackTarget(track, ring) < 0 || trackTarget(track, status.rings[i - 1]) > trackTarget(track, ring))),
  );
  return (
    <article className="kernel">
      <header>
        <h3>{track.kernel}</h3>
        {track.auto_hold &&
          (track.auto_hold_resolved ? (
            <Badge value={[adminExcluded ? "관리자 제외 · 재개 대기" : "원인 해결 · 재개 대기", "warn"]} />
          ) : (
            <Badge value={["자동 배포 멈춤", "bad"]} />
          ))}
        <div className="actions">
          {nextIndex > 0 && (
            <Button
              kind="primary"
              onClick={() =>
                open(
                  <PromoteDialog
                    kernel={track.kernel}
                    ring={status.rings[nextIndex]}
                    version={trackTarget(track, status.rings[nextIndex - 1])}
                  />,
                )
              }
            >
              링 {status.rings[nextIndex]} 승급
            </Button>
          )}
          {status.auto?.enabled &&
            (track.auto_hold ? (
              <Button
                kind="primary"
                onClick={() =>
                  open(
                    <Confirm
                      title="자동 배포 재개"
                      label="재개"
                      onConfirm={(api) =>
                        api("POST", kernelPath(track.kernel) + "/auto", {
                          hold: false,
                        })
                      }
                      message="이 커널의 자동 배포를 재개했습니다."
                    >
                      {track.auto_hold_resolved
                        ? `${adminExcluded ? "관리자 결정" : "원인 해결됨"}: ${track.auto_hold_resolved}\n(멈췄던 이유: ${track.auto_hold})`
                        : `멈춘 이유: ${track.auto_hold}`}
                      {"\n\n"}원인을 확인했다면 재개합니다. 활성 패치는 다음
                      빌드에 다시 포함됩니다.
                    </Confirm>,
                  )
                }
              >
                자동 재개
              </Button>
            ) : (
              <MutationButton
                path={kernelPath(track.kernel) + "/auto"}
                body={{ hold: true }}
                message="이 커널의 자동 배포를 멈췄습니다."
              >
                자동 멈춤
              </MutationButton>
            ))}
          <Button
            kind="danger"
            onClick={() => open(<RollbackDialog track={track} />)}
          >
            롤백
          </Button>
        </div>
      </header>
      <div className="path">
        {status.rings.map((ring, index) => {
          const inRing = hosts.filter((h) => h.ring === ring);
          const good = inRing.filter(
            (h) => hostState(status, h)[1] === "ok",
          ).length;
          const bad = inRing.some((h) => hostState(status, h)[1] === "bad");
          const version = trackTarget(track, ring);
          return (
            <div className="ring-step" key={ring}>
              {index > 0 && (
                <span className="arrow" aria-hidden="true">
                  →
                </span>
              )}
              <div className={"stop" + (version ? " current" : "")}>
                <div className="">
                  링 {ring}
                  {index === 0 && " (카나리)"}
                </div>
                <div className={"ver" + (!version ? " none" : "")}>
                  {ver(version)}
                </div>
                <div className="health">
                  {inRing.length ? (
                    <Badge
                      value={[
                        `${good}/${inRing.length} 정상`,
                        bad ? "bad" : good === inRing.length ? "ok" : "warn",
                      ]}
                    />
                  ) : (
                    <span className="muted">호스트 없음</span>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
      {track.auto_hold && track.auto_hold_resolved ? (
        // 원인이 사라진 멈춤은 오류로 보이지 않게 하고, 재개만 안내합니다.
        <ul className="notes">
          <li className="resolved">
            {adminExcluded ? "관리자 결정" : "원인 해결됨"} ({track.auto_hold_resolved}) · 확인 후 자동 재개를
            누르세요
          </li>
          {notes
            .filter((note) => !note.startsWith("자동 배포 멈춤"))
            .map((note, i) => (
              <li key={i}>{note}</li>
            ))}
        </ul>
      ) : notes.length ? (
        <ul className="notes">
          {notes.map((note, i) => (
            <li
              key={i}
              className={note.startsWith("자동 배포 멈춤") ? "stopped" : ""}
            >
              {note}
            </li>
          ))}
        </ul>
      ) : (
        track.auto_hold && (
          <ul className="notes">
            <li className="stopped">멈춘 이유: {track.auto_hold}</li>
          </ul>
        )
      )}
      <CollectionProblem kernel={track.kernel} upstream={status.upstream?.[track.kernel]} />
    </article>
  );
}
export default function Overview({ navigate }) {
  const { status } = useApp();
  const { open } = useDialog();
  const pending = status.jobs.filter((j) => j.status === "built");
  const badHosts = status.hosts.filter(
    (h) => hostState(status, h)[1] === "bad",
  );
  const failures = status.jobs
    .filter((j) => j.status === "failed" && j.error)
    .slice(0, 3);
  return (
    <>
      <AutoBanner navigate={navigate} />
      <ValidationBanner validation={status.validation} />
      <section>
        <h2>처리할 일</h2>
        {pending.length + badHosts.length + failures.length ? (
          <ul className="todo">
            {pending.map((job) => (
              <li key={"job-" + job.id}>
                <Badge value={["승인대기", "warn"]} />
                <span className="grow">
                  작업 {job.id}{" "}
                  <span className="mono">
                    {job.kernel} {ver(job.version)}
                  </span>{" "}
                  — 새 패치 {(job.new_patch_ids || []).length}건
                </span>
                <Button
                  kind="primary"
                  onClick={() => open(<ReviewDialog job={job} />)}
                >
                  검토
                </Button>
              </li>
            ))}
            {badHosts.map((host) => (
              <li key={host.id}>
                <Badge value={hostState(status, host)} />
                <span className="grow">
                  {host.hostname} —{" "}
                  {host.status.error ||
                    "마지막 보고 " + ago(host.last_seen, status.now)}
                </span>
                <Button onClick={() => navigate("hosts")}>호스트 보기</Button>
              </li>
            ))}
            {failures.map((job) => (
              <li key={"failed-" + job.id}>
                <Badge value={["빌드 실패", "bad"]} />
                <span className="grow">
                  작업 {job.id} {job.kernel} — {job.error}
                </span>
                <Button
                  onClick={() =>
                    open(
                      <TextDialog
                        title={`작업 ${job.id} 빌드 로그`}
                        path={`/api/jobs/${job.id}/log`}
                      />,
                    )
                  }
                >
                  로그
                </Button>
              </li>
            ))}
          </ul>
        ) : (
          <Empty>지금 처리할 일이 없습니다.</Empty>
        )}
      </section>
      <section>
        <h2>커널별 배포</h2>
        {status.tracks.length ? (
          <KernelCards />
        ) : (
          <Empty>
            아직 배포 기록이 없습니다. 호스트가 등록되면 빌더가 그 커널의 패치를
            수집합니다.
          </Empty>
        )}
      </section>
      <Builders />
    </>
  );
}
