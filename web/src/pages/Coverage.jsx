import { useMemo, useState } from "react";
import { SearchIcon } from "lucide-react";
import { useApp, useResource } from "../store.jsx";
import { COVERAGE_STATE, localTime } from "../selectors.js";
import { Empty, Resource, ValidationBanner } from "../ui.jsx";
import { DataTable } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

// 서버(coverage.go 의 coveragePageSize)와 같은 한 페이지 행 수
const PAGE_SIZE = 15;

// 상태 톤(ok/warn/bad)을 shadcn Badge 색으로 옮깁니다. 색은 style.css 의 상태 토큰을 씁니다.
const TONE = {
  ok: "bg-[var(--ok-bg)] text-[var(--ok)]",
  warn: "bg-[var(--warn-bg)] text-[var(--warn)]",
  bad: "bg-[var(--bad-bg)] text-[var(--bad)]",
  "": "bg-muted text-muted-foreground",
};
function StatusBadge({ value }) {
  const [label, tone] = value || ["-", ""];
  return <Badge className={TONE[tone] ?? TONE[""]}>{label}</Badge>;
}

const STATE_ITEMS = [
  { value: "actionable", label: "적용·조치 확인 대상" },
  { value: "all", label: "모든 기록" },
  ...Object.entries(COVERAGE_STATE).map(([value, [label]]) => ({
    value,
    label,
  })),
];

const columns = [
  {
    accessorKey: "cve",
    header: "CVE",
    meta: { className: "whitespace-nowrap font-mono text-[13px]" },
    cell: ({ row }) => (
      <a
        href={"https://ubuntu.com/security/" + encodeURIComponent(row.original.cve)}
        target="_blank"
        rel="noopener noreferrer"
        className="font-medium text-primary underline-offset-4 hover:underline"
      >
        {row.original.cve}
      </a>
    ),
  },
  {
    accessorKey: "priority",
    header: "중요도",
    cell: ({ getValue }) => (
      <Badge variant={getValue() === "high" || getValue() === "critical" ? "destructive" : "outline"}>
        {getValue() || "-"}
      </Badge>
    ),
  },
  {
    accessorKey: "base_status",
    header: "기준 커널",
    cell: ({ getValue }) =>
      getValue() === "affected"
        ? "공식 영향 범위에 해당"
        : COVERAGE_STATE[getValue()]?.[0] || getValue(),
  },
  {
    accessorKey: "vendor_fix_versions",
    header: "공식 수정버전",
    meta: { className: "whitespace-nowrap font-mono text-[13px]" },
    cell: ({ getValue }) =>
      (getValue() || []).join(", ") || (
        <span className="text-muted-foreground">미확인</span>
      ),
  },
  {
    accessorKey: "status",
    header: "처리 상태",
    cell: ({ getValue }) => (
      <StatusBadge value={COVERAGE_STATE[getValue()] || [getValue(), ""]} />
    ),
  },
  {
    id: "records",
    header: "기록",
    meta: { className: "min-w-[220px] whitespace-normal break-words text-[13px]" },
    cell: ({ row }) => {
      const r = row.original;
      return (
        <div className="grid gap-0.5">
          {(r.patch_ids || []).length > 0 && (
            <span className="font-mono">{r.patch_ids.join(", ")}</span>
          )}
          {r.included_patch_ids?.length > 0 && (
            <div>실행 포함: {r.included_patch_ids.join(", ")}</div>
          )}
          {(r.details || []).map((text, i) => (
            <div key={i} className="text-muted-foreground">
              {text}
            </div>
          ))}
        </div>
      );
    },
  },
];

export default function Coverage() {
  const { status, revision } = useApp();
  const [selection, setSelection] = useState({
    host: "",
    state: "actionable",
    q: "",
    offset: 0,
  });
  const [query, setQuery] = useState("");
  const host = status.hosts.some((h) => h.id === selection.host)
    ? selection.host
    : status.hosts[0]?.id;
  const resource = useResource(
    host
      ? "/api/coverage?" + new URLSearchParams({ ...selection, host })
      : null,
    revision,
  );
  const hostItems = useMemo(
    () => status.hosts.map((h) => ({ value: h.id, label: h.hostname })),
    [status.hosts],
  );
  const update = (values) =>
    setSelection((previous) => ({ ...previous, ...values, offset: 0 }));
  if (!host) return <Empty>등록된 호스트가 없습니다.</Empty>;
  return (
    <section>
      <h2>호스트별 CVE 현황</h2>
      <p className="mb-4 text-sm text-muted-foreground">
        Canonical 공식 Ubuntu CVE 목록과 기준 커널·수집 패치·현재 실행 모듈을
        대조합니다. 모듈에 포함됐다는 표시는 해당 CVE의 모든 수정과 공격 차단이
        검증됐다는 뜻이 아닙니다.
      </p>
      <form
        className="mb-4 flex flex-wrap items-center gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          update({ q: query.trim() });
        }}
      >
        <Select
          items={hostItems}
          value={host}
          onValueChange={(value) => update({ host: value })}
        >
          <SelectTrigger aria-label="대조할 호스트" className="w-full bg-card sm:w-auto sm:min-w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {hostItems.map((item) => (
              <SelectItem key={item.value} value={item.value}>
                {item.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          items={STATE_ITEMS}
          value={selection.state}
          onValueChange={(value) => update({ state: value })}
        >
          <SelectTrigger aria-label="CVE 상태" className="w-full bg-card sm:w-auto sm:min-w-48">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {STATE_ITEMS.map((item) => (
              <SelectItem key={item.value} value={item.value}>
                {item.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="relative min-w-0 flex-1 sm:flex-none">
          <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            type="search"
            aria-label="CVE 검색"
            placeholder="CVE-2026-…"
            className="w-full bg-card pl-8 sm:w-56"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
        <Button type="submit" variant="outline">
          검색
        </Button>
      </form>
      <Resource resource={resource}>
        {(data) => (
          <div className="grid gap-4">
            <div className="grid gap-1 rounded-xl border bg-card p-4 text-sm shadow-xs">
              <p className="font-mono font-medium">
                {data.kernel} / 기준 패키지 {data.base_version}
              </p>
              <p className={data.source_stale ? "error" : "text-muted-foreground"}>
                <a
                  href="https://documentation.ubuntu.com/security/security-updates/osv/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary underline-offset-4 hover:underline"
                >
                  Canonical 공식 OSV
                </a>{" "}
                · 목록 {data.inventory_count}건 · 받은 시각{" "}
                {localTime(data.fetched_at)}
                {data.source_stale &&
                  " · 목록이 오래됐거나 시각이 잘못되어 최신 대조가 필요합니다."}
              </p>
              <p className="text-muted-foreground">{data.license}</p>
            </div>
            <ValidationBanner validation={data.validation} />
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(COVERAGE_STATE).map(([id, value]) => (
                <Badge variant="outline" key={id} className="h-6 bg-card px-2.5">
                  {value[0]} {data.counts?.[id] || 0}
                </Badge>
              ))}
            </div>
            <p className="text-sm text-muted-foreground">
              공식 릴리스 정보가 없는 CVE는 ‘정보 부족’으로 남깁니다. 수정버전
              미확인과 미수집을 구분하며 구성별 영향 여부·여러 커밋의 완전성·APT
              배포 여부는 별도 검토가 필요합니다.
            </p>
            <DataTable
              columns={columns}
              data={data.rows || []}
              getRowId={(row) => row.cve}
              empty="조건에 맞는 CVE가 없습니다."
              pagination={{
                offset: data.offset,
                total: data.total,
                pageSize: PAGE_SIZE,
                onOffsetChange: (offset) =>
                  setSelection((old) => ({ ...old, offset })),
              }}
            />
          </div>
        )}
      </Resource>
    </section>
  );
}
