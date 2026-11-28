import { hostPath, kernelPath } from "../api.js";
import { ReviewDialog } from "../dialogs.jsx";
import CollectionProblem from "../CollectionProblem.jsx";
import { useApp } from "../store.jsx";
import {
  ago,
  builderNote,
  cmpVer,
  coveredTag,
  forcedVersion,
  hostState,
  hostTrack,
  hostSecurity,
  hostTarget,
  isHWE,
  isSet,
  latestFor,
  openJob,
  pkgVersion,
  ringTarget,
  tagVersion,
  ver,
} from "../selectors.js";
import {
  Badge,
  Button,
  Confirm,
  Empty,
  MutationButton,
  Table,
  useDialog,
  useMutation,
} from "../ui.jsx";

function HostSecurity({ host }) {
  const security = host.status || {};
  const { required, warning } = hostSecurity(host);
  const eligibility = host.rollout_eligibility;
  const certs = Object.entries(security.enrolled_certs || {}).sort(([a], [b]) => a.localeCompare(b));
  const value = (state) => state && state !== "unknown" ? state : "미확인";
  const enrollment = { enrolled: ["등록됨", "ok"], not_enrolled: ["미등록", "warn"], unknown: ["미확인", "warn"] };
  return <div className="host-security">
    <div><Badge value={[required ? "서명 필요" : "서명 불필요", required ? "warn" : ""]} /></div>
    <dl className="security-signals">
      <div><dt>Firmware</dt><dd>{value(security.firmware)}</dd></div>
      <div><dt>Secure Boot</dt><dd>{value(security.secure_boot)}</dd></div>
      <div><dt>Lockdown</dt><dd>{value(security.lockdown)}</dd></div>
      <div><dt>sig_enforce</dt><dd>{value(security.sig_enforce)}</dd></div>
    </dl>
    {certs.length ? <ul className="cert-enrollments">{certs.map(([key, state]) => <li key={key}><span className="mono">{key}</span> <Badge value={enrollment[state] || enrollment.unknown} /></li>)}</ul> : <div className="muted small-note">인증서 등록 상태 미확인</div>}
    {security.mok_pending && <div className="small-note">MOK 등록 예약됨 · 다음 계획된 재부팅의 콘솔 승인 대기</div>}
    {eligibility?.key_id && <div className="small-note">배포 서명 키: <span className="mono">{eligibility.key_id}</span></div>}
    {eligibility?.status?.startsWith("blocked_") && <div className="warning small-note">배포 제외: {eligibility.reason || "서명 자격 확인 필요"}</div>}
    {warning && <div className="security-warning small-note">보안 경고: {warning}</div>}
    {eligibility?.warning && eligibility.warning !== warning && <div className="security-warning small-note">배포 경고: {eligibility.warning}</div>}
  </div>;
}

function BuildButton({ host, children, kind }) {
  const { open } = useDialog();
  if (host.status.distribution) return <span className="muted small-note">해당 배포판 빌더에서 후보를 검토하고 collect를 실행하세요.</span>;
  return (
    <Button
      kind={kind}
      onClick={() =>
        open(
          <Confirm
            title="최신 수정 빌드"
            label="빌드 요청"
            onConfirm={(api) =>
              api("POST", kernelPath(hostTrack(host)) + "/refresh")
            }
          >
            {host.status.kernel} 호스트에 적용할 CVE 수정을 수집합니다. 자동
            모드에서는 APT 색인으로 확인한 Ubuntu 정식 배포 버전까지 빌드합니다.
            적용 가능한 선택 수정만 라이브패치로 만들며 전체 커널 업그레이드와
            같은 의미는 아닙니다. 빌드가 끝나면 검토·승인 뒤 업데이트할 수
            있습니다.
          </Confirm>,
        )
      }
    >
      {children}
    </Button>
  );
}
function PurgeAction({ host, upstream }) {
  const { open } = useDialog();
  const path = kernelPath(hostTrack(host)) + "/purge";
  if (isSet(upstream.purge_requested_at))
    return (
      <>
        <span className="muted small-note">
          빌드 서버 자료 삭제 요청됨 · 빌더의 다음 작업 확인 때 처리
        </span>
        <MutationButton path={path} body={{ cancel: true }}>
          삭제 요청 취소
        </MutationButton>
      </>
    );
  return (
    <Button
      onClick={() =>
        open(
          <Confirm
            title="빌드 서버 자료 삭제"
            label="삭제 요청"
            danger
            onConfirm={(api) => api("POST", path)}
          >
            {host.status.kernel} 의 빌드 서버 자료(격리 빌드 캐시, 디버그 심볼·커널
            패키지, 남은 시험 기록)를 지웁니다. 빌드 서버가 최근 커널 범위 밖인지 다시
            확인한 뒤 지우며, 실행 중인 커널은 지우지 않습니다. 컨트롤러의 패치·빌드
            기록과 호스트에 적용된 라이브패치는 그대로 남습니다.
          </Confirm>,
        )
      }
    >
      빌드 서버 자료 삭제
    </Button>
  );
}
function KernelUpdate({ host }) {
  const { status } = useApp();
  const { open } = useDialog();
  if (host.rollout_eligibility?.status === "blocked_unsupported") return <span className="warning small-note">{host.rollout_eligibility.reason}</span>;
  if (isHWE(host)) return <span className="muted">-</span>;
  const mine = pkgVersion(host),
    upstream = status.upstream?.[hostTrack(host)];
  const latest = tagVersion(upstream?.latest_tag),
    covered = tagVersion(coveredTag(status, host));
  const excluded = status.unpatchable.filter(
    (u) => u.kernel === hostTrack(host),
  ).length;
  const effective =
    covered && (!mine || cmpVer(covered, mine) > 0) ? covered : mine;
  const behind = effective && latest && cmpVer(effective, latest) < 0;
  const release = latestFor(status, host),
    target = hostTarget(status, host),
    ring = ringTarget(status, host);
  const job = openJob(status, hostTrack(host));
  let action;
  if (target < 0) action = <span className="warning small-note">출시 전 배포 중 — 변경은 링 배포·롤백에서 진행하세요.</span>;
  else if (job?.status === "built" && job.version > Math.max(release, target, host.status.version))
    action = (
      <Button kind="primary" onClick={() => open(<ReviewDialog job={job} />)}>
        최신 누적 v{job.version} 검토·승인
      </Button>
    );
  else if (release > Math.max(target, host.status.version))
    action = (
      <Button
        kind="primary"
        onClick={() =>
          open(
            <Confirm
              title="최신 누적본으로 바로 업데이트"
              label={`v${release} 적용`}
              onConfirm={(api) => api("POST", hostPath(host) + "/update-now", { kernel: hostTrack(host), version: release })}
            >
              <strong>{host.hostname}: v{host.status.version} → 최신 누적 v{release}</strong>
              <p>중간 버전을 설치하지 않고, 빌드·승인된 누적 모듈 하나로 바로 적용합니다.</p>
              링 {host.ring}의 목표({ver(ring)})와 관찰 시간을
              건너뜁니다. 재부팅하지 않으며 다음 보고 때 적용을 시작합니다.
            </Confirm>,
          )
        }
      >
        최신 누적 v{release} 적용
      </Button>
    );
  else if (host.status.version < target)
    action = (
      <span className="muted small-note">
        v{target} 적용 대기 (다음 보고 때)
      </span>
    );
  else if (upstream?.outside)
    action = <PurgeAction host={host} upstream={upstream} />;
  else if (job)
    action = (
      <span className="muted small-note">
        빌드 {job.status === "running" ? "중" : "대기"} (작업 {job.id})
      </span>
    );
  else if (upstream?.problem)
    action = <BuildButton host={host}>다시 시도</BuildButton>;
  else if (isSet(upstream?.refresh_requested_at))
    action = (
      <span className="muted small-note">
        빌드 요청됨 · 빌더의 다음 작업 확인 때 처리
      </span>
    );
  else if (
    isSet(upstream?.refresh_taken_at) &&
    new Date(status.now) - new Date(upstream.refresh_taken_at) < 900000
  )
    action = (
      <span className="muted small-note">
        {upstream.refresh_taken_by || "빌더"}가 수집 중
      </span>
    );
  else if (
    behind &&
    upstream?.collected_tag &&
    cmpVer(tagVersion(upstream.collected_tag), latest) >= 0
  )
    action = (
      <>
        <span className="muted small-note">
          선택 경로의 수집 완료 · 제외·미수집 수정은 별도 검토와 커널 업데이트
          필요
        </span>
        <BuildButton host={host}>다시 빌드</BuildButton>
      </>
    );
  else if (behind || !latest)
    action = (
      <BuildButton host={host} kind={behind ? "primary" : ""}>
        {behind ? "최신까지 빌드" : "확인·빌드"}
      </BuildButton>
    );
  return (
    <div className="kup">
      {!mine ? (
        <span className="muted">버전 모름</span>
      ) : !latest ? (
        <>
          <span className="mono">{mine}</span>
          <span className="muted small-note">최신 확인 전</span>
        </>
      ) : behind ? (
        <>
          <span className="mono">
            {effective} → {latest}
          </span>
          <Badge value={["뒤처짐", "warn"]} />
        </>
      ) : (
        <>
          <span className="mono">{latest}</span>
          <Badge
            value={[
              covered && effective === covered && covered !== mine
                ? "선택 CVE 반영"
                : "설치 커널 최신",
              excluded ? "warn" : "ok",
            ]}
          />
        </>
      )}
      {covered && effective === covered && covered !== mine && (
        <span className="muted small-note">
          커널 {mine} + 라이브패치 v{host.status.version} ({covered}까지 수집한
          선택 CVE)
        </span>
      )}
      {excluded > 0 && (
        <span className="error small-note">
          라이브패치 제외 수정 {excluded}건 · 별도 검토·완화 조치 또는 커널
          업데이트 필요
        </span>
      )}
      <CollectionProblem kernel={hostTrack(host)} upstream={upstream} />
      {upstream?.outside && (
        <span className="muted small-note">빌드 서버: {upstream.outside}</span>
      )}
      {upstream?.outside && isSet(upstream.purged_at) && (
        <span className="muted small-note">
          빌드 서버 자료 삭제 {ago(upstream.purged_at, status.now)}: {upstream.purge_result}
        </span>
      )}
      {!host.status.distribution && !latest && !upstream?.problem && !upstream?.outside && (
        <span className="error small-note">
          {builderNote(status, hostTrack(host))}
        </span>
      )}
      {action}
      {forcedVersion(host) > ring && <MutationButton path={hostPath(host) + "/update-now"} body={{ cancel: true }}>
        즉시 업데이트 취소
      </MutationButton>}
    </div>
  );
}
// 준비된 새 GA 커널로 바로 점프(재부팅)할 수 있는지와, 막혔다면 그 이유.
// 서버(rebootProblem)와 같은 조건이며 승인·실행 직전에 서버가 다시 검사합니다.
function jumpBlocker(status, host) {
  if (host.reboot_policy !== "drain") return "재부팅 정책이 drain 이 아님 (kpctl host set -policy drain)";
  if (host.vm_count < 0) return "VM 수 미확인";
  if (host.vm_count > 0) return `VM ${host.vm_count}대 남음 · 옮긴 뒤 가능`;
  if (host.status.kernel_prepare?.state === "preparing") return "디스크 커널 준비 중";
  if (host.status.error) return "호스트 오류 확인 필요";
  if (!host.status.boot_id) return "부팅 ID 를 보고하는 새 에이전트 필요";
  const age = new Date(status.now) - new Date(host.last_seen);
  if (!(age <= 120000)) return "호스트 보고가 2분 넘게 없음";
  return "";
}
// 커널 점프 1단계: 다음 공식 GA 커널을 디스크에 설치(준비)하도록 요청. 재부팅하지 않습니다.
function gaKernelFromTag(tag) {
  const m = /^Ubuntu-((?:5\.15\.0|6\.8\.0|7\.0\.0)-(\d+))\.\d+$/.exec(tag || "");
  return m ? { kernel: m[1] + "-generic", abi: Number(m[2]) } : null;
}
function KernelPrepare({ host }) {
  const { status } = useApp();
  const { open } = useDialog();
  if (host.status.distribution || host.status.identity_error) return null;
  const kernel = host.status.kernel || "";
  const current = /^(?:5\.15\.0|6\.8\.0|7\.0\.0)-(\d+)-generic$/.exec(kernel);
  const latest = gaKernelFromTag(status.upstream?.[kernel]?.latest_tag);
  if (!current || !latest || isHWE(host) || latest.abi <= Number(current[1]) || !latest.kernel.startsWith(kernel.split("-")[0]))
    return null;
  if (host.reboot_approval || host.reboot_request_id || host.status.kernel_prepare?.state === "preparing") return null;
  if (host.reboot_policy !== "drain")
    return <span className="muted small-note">{latest.kernel} 점프 불가: 재부팅 정책이 drain 이 아님 (kpctl host set -policy drain)</span>;
  const path = hostPath(host) + "/prepare-kernel";
  // 실패한 뒤에는 원인을 고치고 바로 다시 요청할 수 있게 요청 버튼을 보여 줍니다 (재시도 대기 건너뜀)
  const failed = host.status.kernel_prepare?.state === "failed" && host.status.kernel_prepare.kernel === kernel;
  if (host.kernel_prepare_request?.kernel === kernel && !failed)
    return (
      <>
        <span className="muted small-note">
          {latest.kernel} 설치 요청됨 · 에이전트 다음 보고 때 시작 (끝나면 커널 점프 버튼이 생김)
        </span>
        <MutationButton path={path} body={{ cancel: true }}>
          준비 요청 취소
        </MutationButton>
      </>
    );
  return (
    <Button
      kind="primary"
      onClick={() =>
        open(
          <Confirm
            title="커널 점프 1단계: 새 커널 준비"
            label="설치 요청"
            onConfirm={(api) => api("POST", path, { kernel })}
          >
            <strong>
              {host.hostname}: {kernel} → {latest.kernel}
            </strong>
            <p>
              공식 Ubuntu 저장소의 서명 검증된 {latest.kernel} 커널을 현재
              커널 옆에 설치하고 부팅 항목을 준비합니다. 재부팅하지 않으며 VM
              은 그대로입니다. 준비가 끝나면 이 자리에 커널 점프(재부팅 승인)
              버튼이 나타납니다.
            </p>
          </Confirm>,
        )
      }
    >
      {failed ? "원인 해결 후 다시 준비" : "새 커널 준비"} → {latest.kernel}
    </Button>
  );
}
function KernelJump({ host }) {
  const { status } = useApp();
  const { open } = useDialog();
  const target = host.status.boot_target;
  if (!target?.id) return <KernelPrepare host={host} />;
  if (isHWE(host) || host.reboot_approval || host.reboot_request_id) return null;
  const blocker = jumpBlocker(status, host);
  if (blocker)
    return (
      <span className="muted small-note">
        {target.kernel} 점프 불가: {blocker}
      </span>
    );
  const jump = async (api) => {
    if (!host.cordoned) await api("POST", hostPath(host) + "/cordon", { on: true });
    try {
      return await api("POST", hostPath(host) + "/reboot", { target_id: target.id });
    } catch (err) {
      if (!host.cordoned) err.message = "신규 VM 배치 차단은 적용됐습니다(필요하면 차단 해제). 재부팅 승인 실패: " + err.message;
      throw err;
    }
  };
  return (
    <Button
      kind="danger"
      onClick={() =>
        open(
          <Confirm
            title="커널 점프"
            label="이 커널로 재부팅 승인"
            danger
            onConfirm={jump}
            message={host.hostname + " 커널 점프(재부팅)를 승인했습니다."}
          >
            <strong>
              {host.hostname}: {host.status.kernel} → {target.kernel}
            </strong>
            <p>
              {!host.cordoned && "먼저 신규 VM 배치를 막고(드레인), "}
              준비된 커널로 5분 내 한 번만 재부팅합니다. 실행 중인 서비스가
              중단됩니다. 실행 직전에 VM·현재 부팅·파일·승인 유효성을 다시
              검사합니다.
            </p>
          </Confirm>,
        )
      }
    >
      커널 점프 → {target.kernel}
    </Button>
  );
}
function HostActions({ host }) {
  const { open } = useDialog();
  const dispatched = isSet(host.reboot_approval?.dispatched_at);
  return (
    <div className="actions">
      {host.cordoned ? (
        <MutationButton
          path={hostPath(host) + "/cordon"}
          body={{ on: false }}
          disabled={dispatched}
          message={host.hostname + ": 배치 차단을 풀었습니다."}
        >
          차단 해제
        </MutationButton>
      ) : (
        <Button
          onClick={() =>
            open(
              <Confirm
                title="드레인 시작"
                label="드레인"
                onConfirm={(api) =>
                  api("POST", hostPath(host) + "/cordon", { on: true })
                }
                message={host.hostname + ": 신규 VM 배치를 막았습니다."}
              >
                {host.hostname}에 신규 VM 배치를 막습니다.
              </Confirm>,
            )
          }
        >
          드레인
        </Button>
      )}
      {host.reboot_approval && !dispatched && (
        <MutationButton
          path={hostPath(host) + "/reboot"}
          body={{ cancel: true }}
          message="재부팅 승인을 취소했습니다."
        >
          승인 취소
        </MutationButton>
      )}
      {dispatched && (
        <span className="muted small-note">
          재부팅 실행 전달됨 · 실제 부팅 결과 대기
        </span>
      )}
      <Button
        kind="danger"
        onClick={() =>
          open(
            <Confirm
              title="호스트 등록 삭제"
              label="등록 삭제"
              danger
              onConfirm={(api) => api("DELETE", hostPath(host))}
              message={host.hostname + " 등록을 삭제했습니다."}
            >
              {host.hostname}의 등록을 지웁니다. 서버를 폐기할 때만 쓰세요.
              호스트의 패치와 에이전트는 그대로 남습니다.
            </Confirm>,
          )
        }
      >
        등록 삭제
      </Button>
    </div>
  );
}
function HostRow({ host }) {
  const { status } = useApp();
  const action = useMutation({ close: false });
  return (
    <tr>
      <td>
        <div className="host-cell">
          <span className="mono host-name">{host.hostname}</span>
          <div className="host-meta">
            <Badge value={hostState(status, host)} />
            <select
              className="small"
              aria-label={host.hostname + " 링"}
              value={host.ring}
              disabled={action.busy}
              onChange={(event) => {
                const ring = Number(event.target.value);
                void action.execute(
                  (api) => api("POST", hostPath(host), { ring }),
                  host.hostname + "를 링 " + ring + "로 옮겼습니다.",
                );
              }}
            >
              {status.rings.map((ring) => (
                <option key={ring} value={ring}>
                  링 {ring}
                </option>
              ))}
            </select>
          </div>
          {host.status.error && (
            <div className="error small-note">{host.status.error}</div>
          )}
        </div>
      </td>
      <td className="col-kernel">
        <div className="mono muted small-note">
          {host.status.kernel || "-"}
        </div>
        <KernelUpdate host={host} />
        <KernelJump host={host} />
      </td>
      <td className="mono">
        {ver(host.status.version)} / {ver(hostTarget(status, host))}
        {ringTarget(status, host) >= 0 && forcedVersion(host) > ringTarget(status, host) && (
          <div className="muted small-note">
            즉시 업데이트 (링 목표 {ver(ringTarget(status, host))})
          </div>
        )}
      </td>
      <td className="col-security"><HostSecurity host={host} /></td>
      <td className="col-reboot">
        {host.status.kernel_prepare?.state === "preparing" && (
          <div className="small-note">공식 커널 자동 준비 중</div>
        )}
        {host.status.kernel_prepare?.state === "failed" && (
          <div className="error small-note">
            공식 커널 준비 실패: {host.status.kernel_prepare.error}
            {isSet(host.status.kernel_prepare.next_attempt_at) && (
              <div>다음 시도: {new Date(host.status.kernel_prepare.next_attempt_at).toLocaleString()}</div>
            )}
          </div>
        )}
        {host.status.boot_target
          ? host.status.boot_target.kernel + " · 관리자 승인 대기"
          : host.status.boot_problem || "준비 정보 없음"}
        {host.reboot_result && (
          <div
            className={
              host.reboot_result.status === "booted" ? "muted" : "error"
            }
          >
            {host.reboot_result.status}: {host.reboot_result.detail}
          </div>
        )}
      </td>
      <td>
        <div className="host-ops">
          <span>
            정책 <strong>{host.reboot_policy}</strong>
          </span>
          <span className={host.cordoned ? "" : "muted"}>
            {host.cordoned
              ? "드레인 중 · VM " + (host.vm_count < 0 ? "?" : host.vm_count)
              : "드레인 안 함"}
          </span>
          <span className="muted">{ago(host.last_seen, status.now)} 보고</span>
        </div>
      </td>
      <td>
        <HostActions host={host} />
      </td>
    </tr>
  );
}
export default function Hosts() {
  const { status } = useApp();
  const excluded = status.hosts.filter((host) => host.rollout_eligibility?.status?.startsWith("blocked_"));
  if (!status.hosts.length)
    return (
      <Empty>
        등록된 호스트가 없습니다. bootstrap 또는 kpctl install로 등록하세요.
      </Empty>
    );
  return (
    <section>
      <h2>호스트 {status.hosts.length}대</h2>
      {excluded.length > 0 && <p className="warning">배포 제외 {excluded.length}대 · 호스트별 보안·서명 열에서 사유를 확인하세요. 제외된 호스트는 다른 호스트의 링 승급을 막지 않습니다.</p>}
      <p className="hint">누적 패치는 중간 버전 설치 없이 최신 승인 버전으로 바로 적용할 수 있습니다.</p>
      <div className="hosts-table">
        <Table
          headers={[
            "호스트",
            "커널",
            "적용/목표",
            "보안·서명",
            "다음 재부팅 커널",
            "운영",
            "호스트 조작",
          ]}
        >
          {status.hosts.map((host) => (
            <HostRow key={host.id} host={host} />
          ))}
        </Table>
      </div>
    </section>
  );
}
