import { useState } from "react";
import { kernelPath } from "./api.js";
import { Button, Confirm, Field, useDialog } from "./ui.jsx";

export function ExcludeCommitDialog({ kernel, upstream }) {
  const [reason, setReason] = useState("");
  const failure = upstream.problem_failure;
  return (
    <Confirm
      title="미해결 커밋 관리자 제외"
      label="제외하고 수집 계속"
      disabled={!reason.trim()}
      danger
      message="관리자 제외를 기록하고 수집을 요청했습니다. CVE는 미해결이며 자동 배포는 재개하지 않습니다."
      onConfirm={(api) => api("POST", kernelPath(kernel) + "/commits/" + encodeURIComponent(failure.commit) + "/exclude", {
        reason: reason.trim(), problem_ref: upstream.problem_at,
      })}
    >
      <p>{kernel}의 {failure.commit.slice(0, 12)}만 시험에서 제외합니다. {(failure.cves || []).join(", ")}는 미해결로 남습니다. 자동 배포 재개는 별도 판단입니다.</p>
      <Field label="제외 사유 (필수)">
        {(id) => <textarea id={id} required maxLength={1000} value={reason} onChange={(event) => setReason(event.target.value)} />}
      </Field>
    </Confirm>
  );
}

const KIND = {
  busy: "빌드 사용 중 · 다음 확인 때 재시도",
  environment: "빌드 환경 오류 · 환경 확인 필요",
  unsupported: "도구가 지원하지 않는 변경 · 새 커널로 업데이트 권장 또는 관리자 결정 필요",
  artifact: "산출물 검증 실패 · 배포 차단",
  unknown: "실패 원인 미확인 · 관리자 검토 필요",
};

export default function CollectionProblem({ kernel, upstream }) {
  const { open } = useDialog();
  if (!upstream?.problem) return null;
  return <div className="small-note">
    {KIND[upstream.problem_kind] && <strong>{KIND[upstream.problem_kind]}</strong>}
    <div className="error">빌드 서버: {upstream.problem}</div>
    {upstream.latest_tag && <div className="muted">확인된 정식 배포 태그: {upstream.latest_tag}</div>}
    {upstream.problem_failure?.commit && upstream.problem_kind !== "busy" && <Button onClick={() => open(<ExcludeCommitDialog kernel={kernel} upstream={upstream} />)}>이 커밋 제외하고 수집 계속</Button>}
  </div>;
}
