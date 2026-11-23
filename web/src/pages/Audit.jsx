import { useApp, useResource } from "../store.jsx";
import { Resource } from "../ui.jsx";

export default function Audit() {
  const { revision } = useApp();
  const resource = useResource("/api/audit", revision);
  return (
    <section>
      <h2>최근 500줄 (최신이 위)</h2>
      <Resource resource={resource}>
        {(data) => (
          <pre className="log">
            {String(data).split("\n").reverse().join("\n") || "(기록 없음)"}
          </pre>
        )}
      </Resource>
    </section>
  );
}
