import { useEffect, useState } from "react";
import { useResource } from "../store.jsx";
import { Badge, Button, Field, Resource, Table, useMutation } from "../ui.jsx";
import { localTime } from "../selectors.js";

function SigningKeys({ signing }) {
  if (!signing) return <section><h2>서명 키</h2><p className="muted">컨트롤러가 서명 키 정보를 보고하지 않았습니다.</p></section>;
  return <section>
    <h2>서명 키</h2>
    <p className="hint">서명 모드: <strong>{signing.mode || "미확인"}</strong> · 인증서 등록 예약과 콘솔 승인 비밀번호 조회는 관리자 CLI에서 관리합니다.</p>
    {signing.keys?.length ? <Table headers={["키 ID", "활성", "인증서 만료", "등록 호스트", "경고"]}>{signing.keys.map((key) => <tr key={key.id}>
      <td className="mono">{key.id}</td>
      <td>{key.active ? <Badge value={["활성", "ok"]} /> : "이전 키"}</td>
      <td>{key.expires_at ? localTime(key.expires_at) : "미확인"}</td>
      <td>{key.enrolled_hosts ?? 0}대</td>
      <td className={key.warning ? "security-warning" : "muted"}>{key.warning || "-"}</td>
    </tr>)}</Table> : <p className="muted">설정된 공개 서명 키가 없습니다.</p>}
    {(signing.warnings || []).map((warning, index) => <p className="warning" key={index}>{warning}</p>)}
  </section>;
}

const copy = (value) => ({
  ...value,
  min_soak_minutes: { ...(value.min_soak_minutes || {}) },
});
function SettingsForm({ initial, reset }) {
  const [snapshot, setSnapshot] = useState(initial);
  const [draft, setDraft] = useState(() => copy(initial.current));
  useEffect(() => {
    setSnapshot(initial);
    setDraft(copy(initial.current));
  }, [initial]);
  const action = useMutation({ close: false });
  const update = (field, value) =>
    setDraft((old) => ({ ...old, [field]: value }));
  const numeric = (value, name, min) => {
    if (
      String(value).trim() === "" ||
      !Number.isSafeInteger(Number(value)) ||
      Number(value) < min
    )
      throw new Error(`${name}: ${min} 이상의 정수를 넣으세요.`);
    return Number(value);
  };
  const save = (event) => {
    event.preventDefault();
    void action.execute(async (api) => {
      const body = {
        auto_enabled: draft.auto_enabled,
        auto_approve_only: draft.auto_approve_only,
        auto_soak_minutes: numeric(
          draft.auto_soak_minutes,
          "자동 관찰 시간",
          0,
        ),
        host_stale_minutes: numeric(
          draft.host_stale_minutes,
          "연락 끊김 기준",
          1,
        ),
        job_timeout_minutes: numeric(
          draft.job_timeout_minutes,
          "빌드 제한 시간",
          10,
        ),
        min_soak_minutes: Object.fromEntries(
          snapshot.rings
            .slice(1)
            .map((ring) => [
              ring,
              numeric(
                draft.min_soak_minutes[ring] ?? 0,
                `링 ${ring} 관찰 시간`,
                0,
              ),
            ]),
        ),
      };
      const result = await api("POST", "/api/settings", body);
      setSnapshot(result);
      setDraft(copy(result.current));
      return result;
    }, "설정을 저장했습니다.");
  };
  const number = (field, label, help, min) => (
    <Field label={label} help={help}>
      {(id) => (
        <span className="num-field">
          <input
            id={id}
            aria-describedby={id + "-help"}
            type="number"
            min={min}
            step="1"
            required
            disabled={action.busy}
            value={draft[field]}
            onChange={(event) => update(field, event.target.value)}
          />
          <span className="muted">분</span>
          {String(snapshot.current[field]) !== String(snapshot.file[field]) && (
            <span className="muted small-note">
              설정 파일 값: {String(snapshot.file[field])}
            </span>
          )}
        </span>
      )}
    </Field>
  );
  return (
    <form className="settings-form" onSubmit={save}>
      <SigningKeys signing={snapshot.signing} />
      <section>
        <h2>자동 배포</h2>
        <div className="settings">
          <Field
            label="자동 배포"
            help="새 빌드를 자동 승인하고 링 순서대로 넘깁니다. 끄면 사람이 승인·승급합니다."
          >
            {(id) => (
              <input
                id={id}
                type="checkbox"
                checked={draft.auto_enabled}
                disabled={action.busy}
                onChange={(event) =>
                  update("auto_enabled", event.target.checked)
                }
              />
            )}
          </Field>
          <Field
            label="첫 번째 링까지만 자동"
            help="카나리 링까지만 자동으로 배포하고 다음 링은 사람이 승급합니다."
          >
            {(id) => (
              <input
                id={id}
                type="checkbox"
                checked={draft.auto_approve_only}
                disabled={action.busy}
                onChange={(event) =>
                  update("auto_approve_only", event.target.checked)
                }
              />
            )}
          </Field>
          {number(
            "auto_soak_minutes",
            "자동 승급 전 관찰",
            "이전 링에서 관찰할 최소 시간입니다. 1440분 = 24시간.",
            0,
          )}
        </div>
      </section>
      <section>
        <h2>링</h2>
        <div className="settings">
          {snapshot.rings.slice(1).map((ring, i) => (
            <Field
              key={ring}
              label={`링 ${ring} 승급 전 최소 관찰`}
              help={`링 ${snapshot.rings[i]}에 배포한 뒤 기다릴 시간입니다. 수동 승급에도 적용되며 0은 제한 없음입니다.`}
            >
              {(id) => (
                <span className="num-field">
                  <input
                    id={id}
                    type="number"
                    min="0"
                    step="1"
                    required
                    disabled={action.busy}
                    value={draft.min_soak_minutes[ring] ?? 0}
                    onChange={(event) =>
                      setDraft((old) => ({
                        ...old,
                        min_soak_minutes: {
                          ...old.min_soak_minutes,
                          [ring]: event.target.value,
                        },
                      }))
                    }
                  />
                  <span className="muted">분</span>
                  <span className="muted small-note">
                    설정 파일 값: {snapshot.file.min_soak_minutes?.[ring] || 0}
                  </span>
                </span>
              )}
            </Field>
          ))}
          {snapshot.rings.length < 2 && (
            <p className="muted">링이 하나뿐입니다.</p>
          )}
        </div>
      </section>
      <section>
        <h2>감시</h2>
        <div className="settings">
          {number(
            "host_stale_minutes",
            "연락 끊김 기준",
            "보고가 이 시간 넘게 없으면 연락 끊김으로 표시하고 승급을 막습니다.",
            1,
          )}
          {number(
            "job_timeout_minutes",
            "빌드 제한 시간",
            "작업의 상태 보고가 이 시간 넘게 없으면 다음 빌더 조회 때 대기열로 돌립니다.",
            10,
          )}
        </div>
      </section>
      {action.error && (
        <p role="alert" className="error">
          {action.error}
        </p>
      )}
      <div className="set-foot">
        <p className="hint">
          저장하면 재시작 없이 적용되고 감사 로그에 남습니다. 운영 설정은
          controller.json보다 우선합니다. 자동 라이브패치 설정은 재부팅을
          승인하지 않습니다.
        </p>
        <Button disabled={action.busy} onClick={reset}>
          되돌리기
        </Button>
        <button className="btn primary" type="submit" disabled={action.busy}>
          {action.busy ? "저장 중…" : "저장"}
        </button>
      </div>
    </form>
  );
}
export default function Settings() {
  const [reload, setReload] = useState(0);
  const resource = useResource("/api/settings", reload);
  return (
    <Resource resource={resource}>
      {(data) => (
        <SettingsForm
          initial={data}
          reset={() => setReload((value) => value + 1)}
        />
      )}
    </Resource>
  );
}
