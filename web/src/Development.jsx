import { useEffect, useState } from "react";

export function DevelopmentBanner() {
  const [scenario, setScenario] = useState("mixed");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/dev/info", {
      credentials: "omit",
      headers: { Authorization: "Bearer demo-admin-token" },
      signal: controller.signal,
    })
      .then((response) => {
        if (!response.ok) throw new Error("가상 환경 정보를 읽지 못했습니다.");
        return response.json();
      })
      .then((info) => setScenario(info.scenario))
      .catch((error) => {
        if (error.name !== "AbortError") setError(error.message);
      });
    return () => controller.abort();
  }, []);
  const reset = async () => {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/dev/reset", {
        method: "POST",
        credentials: "omit",
        headers: {
          Authorization: "Bearer demo-admin-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ scenario }),
      });
      if (!response.ok) throw new Error("가상 환경을 초기화하지 못했습니다.");
      window.location.reload();
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };
  return (
    <aside className="development-banner" aria-label="개발 환경">
      <strong>개발 환경 · 가상 데이터</strong>
      <span>
        조작은 메모리에만 반영됩니다. 실제 서버의 빌드·배포·재부팅은 실행하지
        않습니다.
      </span>
      <label>
        시나리오{" "}
        <select
          value={scenario}
          disabled={busy}
          onChange={(event) => setScenario(event.target.value)}
        >
          <option value="mixed">정상·오프라인·전환 혼합</option>
          <option value="healthy">정상 호스트</option>
          <option value="empty">빈 환경</option>
          <option value="source-error">CVE 목록 오류</option>
        </select>
      </label>
      <button
        type="button"
        className="btn small"
        disabled={busy}
        onClick={reset}
      >
        가상 데이터 초기화
      </button>
      <span className="hint">데모 토큰: demo-admin-token</span>
      {error && <span role="alert">{error}</span>}
    </aside>
  );
}
