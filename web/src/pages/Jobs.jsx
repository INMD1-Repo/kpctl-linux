import { ReviewDialog } from "../dialogs.jsx";
import Builders from "../Builders.jsx";
import { useApp } from "../store.jsx";
import { ago, JOB_STATUS, ver } from "../selectors.js";
import { Badge, Button, Empty, Table, TextDialog, useDialog, VMTestEvidence } from "../ui.jsx";

export default function Jobs() {
  const { status } = useApp();
  const { open } = useDialog();
  if (!status.jobs.length) return <><Builders /><Empty>빌드 작업이 없습니다.</Empty></>;
  return (
    <><Builders />
    <section>
      <h2>최근 작업 30개</h2>
      <Table
        headers={[
          "작업",
          "커널",
          "버전",
          "상태",
          "패치",
          "요청",
          "승인",
          "생성",
          "오류",
          "VM 시험",
          "작업 조작",
        ]}
      >
        {status.jobs.map((job) => (
          <tr key={job.id}>
            <td className="mono">{job.id}</td>
            <td className="mono">{job.kernel}</td>
            <td className="mono">{ver(job.version)}</td>
            <td>
              <Badge value={JOB_STATUS[job.status] || [job.status, ""]} />
              {job.urgent && " 긴급"}
              {job.prerelease && <Badge value={["출시 전", "warn"]} />}
            </td>
            <td>
              {(job.patch_ids || []).length} (새{" "}
              {(job.new_patch_ids || []).length})
            </td>
            <td>{job.requested_by}</td>
            <td>
              {job.approved_by === "auto" ? (
                <Badge value={["자동", "ok"]} />
              ) : (
                job.approved_by || "-"
              )}
            </td>
            <td>{ago(job.created_at, status.now)}</td>
            <td className="wrap">{job.error}</td>
            <td><VMTestEvidence result={job.vm_test} artifacts={job.signing_artifacts} activeKey={job.active_signing_key} label={`작업 ${job.id} VM 시험`} /></td>
            <td>
              <div className="actions">
                <Button
                  kind={job.status === "built" ? "primary" : ""}
                  onClick={() => open(<ReviewDialog job={job} />)}
                >
                  {job.status === "built" ? "검토·승인" : "보기"}
                </Button>
                {["running", "built", "failed", "released"].includes(job.status) && (
                  <Button
                    onClick={() =>
                      open(
                        <TextDialog
                          title={`작업 ${job.id} 빌드 로그`}
                          path={`/api/jobs/${job.id}/log`}
                          live={job.status === "running"}
                        />,
                      )
                    }
                  >
                    {job.status === "running" ? "실시간 로그" : "로그"}
                  </Button>
                )}
              </div>
            </td>
          </tr>
        ))}
      </Table>
    </section>
    </>
  );
}
