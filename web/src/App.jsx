import { useEffect, useState } from "react";
import { AppProvider, useApp } from "./store.jsx";
import { Button, DialogProvider, Empty, useDialog } from "./ui.jsx";
import Overview from "./pages/Overview.jsx";
import Jobs from "./pages/Jobs.jsx";
import Hosts from "./pages/Hosts.jsx";
import Patches from "./pages/Patches.jsx";
import Coverage from "./pages/Coverage.jsx";
import Settings from "./pages/Settings.jsx";
import Audit from "./pages/Audit.jsx";
import { DevelopmentBanner } from "./Development.jsx";
import {
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import { Brand } from "@/components/brand";

//로그인 페이지
function Login() {
  const { login, loginError, pendingLogin } = useApp();
  const [candidate, setCandidate] = useState("");
  return (
    <section className="login">
      <form
        className="login-box"
        onSubmit={(event) => {
          event.preventDefault();
          void login(candidate);
        }}
      >
        <h1 className="login-brand">
          <Brand size="lg" />
        </h1>
        <p className="login-sub">관리자 로그인</p>
        <label htmlFor="token">관리자 토큰</label>
        <input
          id="token"
          type="password"
          autoComplete="off"
          spellCheck={false}
          required
          autoFocus
          value={candidate}
          disabled={pendingLogin}
          onChange={(event) => setCandidate(event.target.value)}
        />
        <p className="hint">
          관리자에게 발급받은 토큰으로 로그인합니다. 이 탭을 닫으면 저장된
          토큰이 지워집니다.
        </p>
        <button className="btn primary" type="submit" disabled={pendingLogin}>
          {pendingLogin ? "확인 중…" : "로그인"}
        </button>
        {loginError && (
          <p className="error" role="alert">
            {loginError}
          </p>
        )}
      </form>
    </section>
  );
}

// Navbar Global
function Dashboard() {
  const { status, error, refresh, logout } = useApp();
  const { isOpen } = useDialog();
  const [tab, setTab] = useState("overview");
  useEffect(() => {
    const timer = setInterval(() => {
      const focused = document.activeElement?.tagName;
      if (
        !isOpen &&
        tab !== "settings" &&
        !["INPUT", "SELECT", "TEXTAREA"].includes(focused) &&
        document.visibilityState !== "hidden"
      )
        void refresh();
    }, 10000);
    return () => clearInterval(timer);
  }, [refresh, isOpen, tab]);
  const pages = {
    overview: <Overview navigate={setTab} />,
    jobs: <Jobs />,
    hosts: <Hosts />,
    patches: <Patches />,
    coverage: <Coverage />,
    settings: <Settings />,
    audit: <Audit />,
  };
  const pending = status.jobs.filter((j) => j.status === "built").length;
  return (
    <SidebarProvider className="max-md:flex-col">
      <AppSidebar
        tab={tab}
        onNavigate={setTab}
        pending={pending}
        who={status.who}
        now={status.now}
        onLogout={() => logout()}
      />
      {/* 휴대폰(768px 미만)에서는 내용 위에 붙는 상단 막대가 되어 스크롤해도 메뉴를 열 수 있습니다 */}
      <div className="p-3 max-md:sticky max-md:top-0 max-md:z-20 max-md:flex max-md:items-center max-md:gap-2 max-md:border-b max-md:bg-background max-md:px-4 max-md:py-2">
        <SidebarTrigger className="max-md:size-10" />
        <span className="md:hidden">
          <Brand />
        </span>
      </div>

      <main>
        {import.meta.env.DEV && import.meta.env.MODE === "mock" && (
          <DevelopmentBanner />
        )}
        {error && (
          <div className="danger-note" role="alert">
            연결 오류: {error} <Button onClick={refresh}>다시 확인</Button>
          </div>
        )}
        {pages[tab]}
      </main>
    </SidebarProvider>
  );
}

function Session() {
  const { token, status, error, notice, refresh, logout } = useApp();
  if (!token) return <Login />;
  return (
    <DialogProvider>
      {status ? (
        <Dashboard />
      ) : (
        <main>
          <Empty>관리자 현황을 불러오는 중…</Empty>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <div className="actions">
            <Button onClick={refresh}>다시 확인</Button>
            <Button onClick={() => logout()}>로그아웃</Button>
          </div>
        </main>
      )}
      {notice && (
        <div
          role={notice.bad ? "alert" : "status"}
          className={"toast" + (notice.bad ? " bad" : "")}
        >
          {notice.message}
        </div>
      )}
    </DialogProvider>
  );
}
export default function App() {
  return (
    <>
      <AppProvider>
        <Session />
      </AppProvider>
    </>
  );
}
