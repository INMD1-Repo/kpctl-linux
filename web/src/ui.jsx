import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { useApp, usePolling, useResource } from "./store.jsx";
import { localTime } from "./selectors.js";

export function Button({ children, kind = "", className = "", ...props }) {
  return (
    <button
      type="button"
      className={`btn small ${kind} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}
export function Badge({ value }) {
  return (
    <span className={"badge " + (value?.[1] || "")}>{value?.[0] || "-"}</span>
  );
}
export function Table({ headers, children }) {
  const ref = useRef(null);
  // 모바일 카드 보기에서 각 칸 위에 열 이름을 보여 주려고 data-label 을 붙입니다.
  useLayoutEffect(() => {
    ref.current?.querySelectorAll(":scope > tbody > tr").forEach((tr) =>
      [...tr.children].forEach((td, i) =>
        td.setAttribute("data-label", headers[i] ?? ""),
      ),
    );
  });
  return (
    <div className="table-wrap rtable">
      <table ref={ref}>
        <thead>
          <tr>
            {headers.map((text) => (
              <th scope="col" key={text || "actions"}>
                {text}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}
export function Empty({ children }) {
  return <p className="empty">{children}</p>;
}

const vmStates = { passed: ["통과", "ok"], failed: ["실패", "bad"], skipped: ["생략", ""], running: ["진행 중", "warn"] };
const vmSteps = { boot: "부팅·서명 강제 확인", negative_signature: "미서명 모듈 거부", load_previous: "이전 누적본 적용", load_new: "새 누적본 적용·전환", replace: "이전 누적본 교체", rollback: "이전 누적본 롤백", smoke: "Smoke 명령", cleanup: "시험 상태 정리", kernel_log: "새 커널 로그 검사" };

export function VMTestEvidence({ result, label = "VM 시험", artifacts, activeKey }) {
  if (!result) return <span className="muted small-note">VM 시험 기록 없음</span>;
  return <details className="vm-evidence">
    <summary>{label} <Badge value={vmStates[result.status] || [result.status || "미확인", "warn"]} /></summary>
    <div className="small-note">시험 모드: {(result.modes || []).join(", ") || "미확인"}</div>
    {result.sha256 && <div className="mono small-note artifact-sha">시험 산출물 SHA256: {result.sha256}</div>}
    {Object.entries(artifacts || {}).map(([key, artifact]) => <div className="mono small-note artifact-sha" key={key}>키 {key}{key === activeKey ? " (활성)" : ""} · SHA256 {artifact.sha256 || "미확인"} <Badge value={vmStates[artifact.vm_test?.status] || ["시험 미확인", "warn"]} /></div>)}
    {result.error && <div className="error small-note">{result.error}</div>}
    {result.steps?.length ? <ol className="vm-steps">{result.steps.map((step, index) => <li key={index}>
      <div><strong>{vmSteps[step.name] || step.name}</strong> <Badge value={vmStates[step.status] || [step.status || "미확인", "warn"]} /></div>
      <div className="mono small-note">{step.mode || "모드 미확인"}{step.key_id && " · 키 " + step.key_id}</div>
      {step.detail && <div className="small-note wrap">{step.detail}</div>}
    </li>)}</ol> : <p className="muted small-note">단계별 기록이 없는 이전 시험 결과입니다.</p>}
  </details>;
}
export function Resource({ resource, children }) {
  if (resource.loading)
    return (
      <p role="status" className="muted">
        불러오는 중…
      </p>
    );
  if (resource.error)
    return (
      <p className="error" role="alert">
        {resource.error}
      </p>
    );
  return children(resource.data);
}
export function Diff({ text }) {
  return (
    <pre>
      {String(text)
        .split("\n")
        .map((line, i) => (
          <span
            key={i}
            className={
              line.startsWith("+") && !line.startsWith("+++")
                ? "diff-add"
                : line.startsWith("-") && !line.startsWith("---")
                  ? "diff-del"
                  : ""
            }
          >
            {line}
            {"\n"}
          </span>
        ))}
    </pre>
  );
}

const DialogContext = createContext(null);
export const useDialog = () => useContext(DialogContext);
export function DialogProvider({ children }) {
  const [content, setContent] = useState(null);
  const [blocked, setBlocked] = useState(false);
  const ref = useRef(null);
  const open = useCallback((element) => {
    setBlocked(false);
    setContent(element);
  }, []);
  const close = useCallback(() => setContent(null), []);
  useEffect(() => {
    if (content && ref.current && !ref.current.open) ref.current.showModal();
    if (!content && ref.current?.open) ref.current.close();
  }, [content]);
  return (
    <DialogContext.Provider
      value={{ open, close, setBlocked, isOpen: Boolean(content) }}
    >
      {children}
      <dialog
        ref={ref}
        aria-labelledby="dialog-title"
        onCancel={(event) => {
          event.preventDefault();
          if (!blocked) close();
        }}
        onClose={() => {
          if (!ref.current?.open) close();
        }}
      >
        {content}
      </dialog>
    </DialogContext.Provider>
  );
}
export function DialogFrame({ title, children, actions, busy = false }) {
  const { close } = useDialog();
  return (
    <div className="dlg">
      <h2 id="dialog-title">{title}</h2>
      <div className="body">{children}</div>
      <div className="foot">
        <Button onClick={close} disabled={busy}>
          닫기
        </Button>
        {actions}
      </div>
    </div>
  );
}

// One mutation per interaction. Closing/escaping a pending dialog is blocked.
export function useMutation({ close = true } = {}) {
  const { api, refresh, notify } = useApp();
  const dialog = useDialog();
  const inFlight = useRef(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const execute = async (operation, message, onError) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError("");
    if (close) dialog.setBlocked(true);
    try {
      const result = await operation(api);
      if (message || result?.message) notify(message || result.message);
      if (close) dialog.close();
      await refresh();
      return result;
    } catch (err) {
      if (err.status !== 401) {
        setError(err.message);
        if (!close) notify(err.message, true);
        onError?.(err);
      }
    } finally {
      inFlight.current = false;
      setBusy(false);
      if (close) dialog.setBlocked(false);
    }
  };
  return { execute, busy, error };
}
export function Confirm({
  title,
  children,
  label = "확인",
  onConfirm,
  message,
  danger = false,
  disabled = false,
}) {
  const action = useMutation();
  return (
    <DialogFrame
      title={title}
      busy={action.busy}
      actions={
        <Button
          kind={danger ? "danger-solid" : "primary"}
          disabled={disabled || action.busy}
          onClick={() => action.execute(onConfirm, message)}
        >
          {action.busy ? "처리 중…" : label}
        </Button>
      }
    >
      <div className={danger ? "danger-note" : "confirm-message"}>
        {children}
      </div>
      {action.error && (
        <p role="alert" className="error">
          {action.error}
        </p>
      )}
    </DialogFrame>
  );
}
export function MutationButton({
  method = "POST",
  path,
  body,
  message,
  children,
  ...props
}) {
  const action = useMutation({ close: false });
  return (
    <Button
      {...props}
      disabled={props.disabled || action.busy}
      onClick={() => action.execute((api) => api(method, path, body), message)}
    >
      {action.busy ? "처리 중…" : children}
    </Button>
  );
}
export function LiveLog({ text, following = true }) {
  const ref = useRef(null);
  useLayoutEffect(() => {
    if (following && ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [text, following]);
  return <pre ref={ref} className="log live-log">{text || '아직 전송된 로그가 없습니다.'}</pre>;
}

export function TextDialog({ title, path, diff = false, live = false }) {
  const [following, setFollowing] = useState(live);
  const { revision, reload } = usePolling(5000, following);
  const resource = useResource(path, revision);
  return (
    <DialogFrame title={title}>
      {live && <div className="actions log-controls">
        <span className="muted">{following ? '5초마다 갱신 · 최신 로그 따라가기' : '자동 갱신 일시 중지'}</span>
        <Button onClick={() => setFollowing(value => !value)}>{following ? '자동 갱신 중지' : '자동 갱신 재개'}</Button>
        <Button onClick={reload}>새로고침</Button>
      </div>}
      <Resource resource={resource}>
        {(data) =>
          diff ? (
            <Diff text={data} />
          ) : (
            live ? <LiveLog text={String(data)} following={following} /> : <pre className="log">{String(data)}</pre>
          )
        }
      </Resource>
    </DialogFrame>
  );
}
export function PatchDetails({ patch }) {
  const [expanded, setExpanded] = useState(false);
  const resource = useResource(
    expanded ? "/api/patches/" + encodeURIComponent(patch.id) + "/diff" : null,
  );
  return (
    <details onToggle={(event) => setExpanded(event.currentTarget.open)}>
      <summary>
        <span className="mono">{patch.id}</span> {(patch.cves || []).join(", ")}{" "}
        {patch.title}
      </summary>
      {expanded && (
        <Resource resource={resource}>
          {(data) => <Diff text={data} />}
        </Resource>
      )}
    </details>
  );
}
export function ValidationBanner({ validation: v }) {
  if (!v) return null;
  const phases = {
    soaking: "24시간 부하 관찰 중",
    promoting: "2차 배포 검증 중",
    rollback_test: "되돌리기·복원 검증 중",
    complete: "검증 완료",
    failed: "검증 중단 · 원인 확인 필요",
  };
  return (
    <div className={v.phase === "failed" ? "danger-note" : "warning"}>
      전용 테스트 환경: {phases[v.phase] || v.phase} · 관찰 기한{" "}
      {localTime(v.eligible_after)} · 마지막 확인 {localTime(v.updated_at)}
      {v.phase === "soaking" &&
        Date.now() - new Date(v.updated_at) > 120000 &&
        " · 검증기 보고가 늦습니다."}
      {v.error && " · " + v.error}
      {v.last_action && (
        <div className="mono">
          {v.last_action.path} · {v.last_action.state}
        </div>
      )}
      {(v.targets || []).map((t) => (
        <div className="mono" key={t.kernel}>
          {t.kernel} ·{" "}
          {Object.entries(t.ring_versions || {})
            .map(([ring, version]) => `링 ${ring} v${version}`)
            .join(", ")}
        </div>
      ))}
    </div>
  );
}
export function Field({ label, help, children }) {
  const id = useId();
  return (
    <div className="set-row">
      <div className="set-label">
        <label htmlFor={id}>{label}</label>
        <p className="hint" id={id + "-help"}>
          {help}
        </p>
      </div>
      <div className="set-control">{children(id)}</div>
    </div>
  );
}
