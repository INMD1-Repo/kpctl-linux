import type { ReactNode } from "react"
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from "@tanstack/react-table"
import {
  ChevronLeftIcon,
  ChevronRightIcon,
  ChevronsLeftIcon,
  ChevronsRightIcon,
} from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

/** 서버가 offset 기반으로 나눠 주는 페이지 정보 */
export type ServerPagination = {
  offset: number
  total: number
  pageSize: number
  onOffsetChange: (offset: number) => void
}

type DataTableProps<TData> = {
  columns: ColumnDef<TData, any>[]
  data: TData[]
  getRowId?: (row: TData, index: number) => string
  pagination?: ServerPagination
  empty?: ReactNode
}

/**
 * shadcn Data Table 패턴(TanStack Table + shadcn Table).
 * 필터·페이지는 서버가 처리하므로 manualPagination 으로 받은 행만 그립니다.
 */
export function DataTable<TData>({
  columns,
  data,
  getRowId,
  pagination,
  empty = "결과가 없습니다.",
}: DataTableProps<TData>) {
  const pageSize = pagination?.pageSize ?? Math.max(data.length, 1)
  const total = pagination?.total ?? data.length
  const pageIndex = pagination ? Math.floor(pagination.offset / pageSize) : 0

  const table = useReactTable({
    data,
    columns,
    getRowId,
    getCoreRowModel: getCoreRowModel(),
    manualPagination: true,
    rowCount: total,
    state: { pagination: { pageIndex, pageSize } },
    onPaginationChange: (updater) => {
      if (!pagination) return
      const next =
        typeof updater === "function"
          ? updater({ pageIndex, pageSize })
          : updater
      pagination.onOffsetChange(next.pageIndex * pageSize)
    },
  })

  const pageCount = Math.max(table.getPageCount(), 1)
  const from = total ? pageIndex * pageSize + 1 : 0
  const to = pageIndex * pageSize + data.length

  return (
    <div className="grid gap-3">
      <div className="rtable overflow-hidden rounded-xl border bg-card shadow-xs">
        <Table>
          <TableHeader className="bg-muted/50">
            {table.getHeaderGroups().map((group) => (
              <TableRow key={group.id} className="hover:bg-transparent">
                {group.headers.map((header) => (
                  <TableHead
                    key={header.id}
                    className="h-9 px-3 text-xs font-medium text-muted-foreground"
                  >
                    {header.isPlaceholder
                      ? null
                      : flexRender(
                          header.column.columnDef.header,
                          header.getContext()
                        )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows.length ? (
              table.getRowModel().rows.map((row) => (
                <TableRow key={row.id}>
                  {row.getVisibleCells().map((cell) => (
                    <TableCell
                      key={cell.id}
                      data-label={
                        typeof cell.column.columnDef.header === "string"
                          ? cell.column.columnDef.header
                          : ""
                      }
                      className={
                        "px-3 py-2.5 align-top " +
                        ((cell.column.columnDef.meta as { className?: string })
                          ?.className ?? "")
                      }
                    >
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext()
                      )}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow className="hover:bg-transparent">
                <TableCell
                  colSpan={columns.length}
                  className="h-24 text-center text-muted-foreground"
                >
                  {empty}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      {pagination && (
        <div className="flex flex-wrap items-center justify-center gap-2 text-sm sm:justify-between">
          <span className="text-muted-foreground">
            {total}건 중 {from}–{to}
          </span>
          <div className="flex items-center gap-1.5">
            <span className="mr-2 text-muted-foreground tabular-nums">
              {pageIndex + 1} / {pageCount} 페이지
            </span>
            <Button
              variant="outline"
              size="icon-sm"
              className="max-md:size-9"
              aria-label="처음"
              disabled={!table.getCanPreviousPage()}
              onClick={() => table.firstPage()}
            >
              <ChevronsLeftIcon />
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="max-md:h-9"
              disabled={!table.getCanPreviousPage()}
              onClick={() => table.previousPage()}
            >
              <ChevronLeftIcon />
              이전
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="max-md:h-9"
              disabled={!table.getCanNextPage()}
              onClick={() => table.nextPage()}
            >
              다음
              <ChevronRightIcon />
            </Button>
            <Button
              variant="outline"
              size="icon-sm"
              className="max-md:size-9"
              aria-label="마지막"
              disabled={!table.getCanNextPage()}
              onClick={() => table.lastPage()}
            >
              <ChevronsRightIcon />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
