import { useState } from "react";
import { kernelPath } from "../api.js";
import { useApp, useResource } from "../store.jsx";
import { knownKernels, PATCH_STATE, localTime } from "../selectors.js";
import {
  Badge,
  Button,
  Confirm,
  Empty,
  MutationButton,
  Resource,
  Table,
  TextDialog,
  useDialog,
  VMTestEvidence,
} from "../ui.jsx";

function PatchVMTest({ patch, jobs }) {
  const tested = jobs.find((job) => job.vm_test && job.patch_ids?.includes(patch.id));
  return <VMTestEvidence result={tested?.vm_test} artifacts={tested?.signing_artifacts} activeKey={tested?.active_signing_key} label={tested ? `작업 ${tested.id} VM 시험` : "VM 시험"} />;
}

export default function Patches() {
  const { status, revision } = useApp();
  const { open } = useDialog();
  const kernels = knownKernels(status);
  const [selection, setSelection] = useState("");
  const kernel = kernels.includes(selection) ? selection : kernels[0] || "";
  const resource = useResource(
    kernel ? kernelPath(kernel) + "/patches" : null,
    revision,
  );
  const unpatchable = status.unpatchable.filter((p) => p.kernel === kernel);
  if (!kernels.length) return <Empty>아직 패치가 없습니다.</Empty>;
  return (
    <>
      <section>
        <div className="toolbar">
          <label htmlFor="patch-kernel">커널</label>
          <select
            id="patch-kernel"
            value={kernel}
            onChange={(event) => setSelection(event.target.value)}
          >
            {kernels.map((k) => (
              <option key={k}>{k}</option>
            ))}
          </select>
          <div className="actions">
            <Button
              onClick={() =>
                open(
                  <Confirm
                    title="다시 빌드"
                    label="빌드 요청"
                    onConfirm={(api) =>
                      api("POST", kernelPath(kernel) + "/build", {
                        urgent: false,
                      })
                    }
                    message="빌드 작업을 만들었습니다."
                  >
                    {kernel}의 활성 패치로 새 누적 빌드를 만듭니다. 패치를
                    켜거나 끈 뒤에 실행하세요.
                  </Confirm>,
                )
              }
            >
              활성 패치로 다시 빌드
            </Button>
          </div>
        </div>
        <Resource resource={resource}>
          {(patches) =>
            patches.length ? (
              <Table
                headers={[
                  "ID",
                  "상태",
                  "출처",
                  "CVE",
                  "제목",
                  "비고",
                  "최근 VM 시험",
                  "패치 조작",
                ]}
              >
                {[...patches].reverse().map((p) => (
                  <tr key={p.id}>
                    <td className="mono">{p.id}</td>
                    <td>
                      <Badge value={PATCH_STATE[p.state] || [p.state, ""]} />
                    </td>
                    <td>
                      {p.source === "ubuntu" ? "Ubuntu " : "수동 "}
                      {p.prerelease && <Badge value={["출시 전", "warn"]} />}
                      <span className="mono muted">
                        {p.commit?.slice(0, 12)}
                      </span>
                    </td>
                    <td className="mono">{(p.cves || []).join(", ")}</td>
                    <td className="title">{p.title}</td>
                    <td className="wrap">{p.reason}</td>
                    <td><PatchVMTest patch={p} jobs={status.jobs} /></td>
                    <td>
                      <div className="actions">
                        <Button
                          onClick={() =>
                            open(
                              <TextDialog
                                title={p.id + " " + p.title}
                                path={
                                  "/api/patches/" +
                                  encodeURIComponent(p.id) +
                                  "/diff"
                                }
                                diff
                              />,
                            )
                          }
                        >
                          diff
                        </Button>
                        <MutationButton
                          path={
                            "/api/patches/" +
                            encodeURIComponent(p.id) +
                            "/state"
                          }
                          body={{
                            state: p.state === "active" ? "disabled" : "active",
                          }}
                          message={
                            p.id + "를 바꿨습니다. 반영하려면 다시 빌드하세요."
                          }
                        >
                          {p.state === "active" ? "끄기" : "켜기"}
                        </MutationButton>
                      </div>
                    </td>
                  </tr>
                ))}
              </Table>
            ) : (
              <Empty>이 커널에는 패치가 없습니다.</Empty>
            )
          }
        </Resource>
      </section>
      {unpatchable.length > 0 && (
        <section>
          <h2>미해결 CVE — 관리자 제외·이전 불가 판정</h2>
          <Table headers={["CVE", "커밋", "제목", "이유·결정", "조작"]}>
            {unpatchable.map((p, i) => (
              <tr key={p.commit || i}>
                <td className="mono">{(p.cves || []).join(", ")}</td>
                <td className="mono">{p.commit?.slice(0, 12)}</td>
                <td className="title">{p.title}</td>
                <td className="wrap">{p.decision && <><strong>미해결 · 관리자 제외</strong><div>{p.decision.by} · {localTime(p.decision.at)}</div><div>기준 {p.decision.input.base_tag} · {p.decision.input.build_tool} · {p.decision.input.image || p.decision.input.profile || "호스트 도구"}</div></>}{p.reason}</td>
                <td>{p.decision && <Button onClick={() => open(<Confirm title="관리자 제외 취소" label="취소하고 재시험" message="제외를 취소하고 재시험을 요청했습니다." onConfirm={(api) => api("DELETE", kernelPath(kernel) + "/commits/" + encodeURIComponent(p.commit) + "/exclude")}>{p.commit.slice(0, 12)}를 다음 수집에서 다시 시험합니다. 자동 배포는 재개하지 않습니다.</Confirm>)}>제외 취소</Button>}</td>
              </tr>
            ))}
          </Table>
        </section>
      )}
    </>
  );
}
