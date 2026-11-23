import type { ComponentType } from "react"
import {
  HammerIcon,
  LayoutDashboardIcon,
  LogOutIcon,
  PackageIcon,
  ScrollTextIcon,
  ServerIcon,
  SettingsIcon,
  ShieldAlertIcon,
} from "lucide-react"

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar"
import { Brand } from "@/components/brand"
export const navItems: {
  id: string
  label: string
  icon: ComponentType<{ className?: string }>
}[] = [
  { id: "overview", label: "개요", icon: LayoutDashboardIcon },
  { id: "jobs", label: "빌드 작업", icon: HammerIcon },
  { id: "hosts", label: "호스트", icon: ServerIcon },
  { id: "patches", label: "패치", icon: PackageIcon },
  { id: "coverage", label: "CVE 현황", icon: ShieldAlertIcon },
  { id: "settings", label: "설정", icon: SettingsIcon },
  { id: "audit", label: "감사 로그", icon: ScrollTextIcon },
]

type AppSidebarProps = {
  tab: string
  onNavigate: (id: string) => void
  pending?: number
  who?: string
  now?: string | number
  onLogout?: () => void
}

export function AppSidebar({
  tab,
  onNavigate,
  pending = 0,
  who,
  now,
  onLogout,
}: AppSidebarProps) {
  // 휴대폰에서는 메뉴가 화면을 덮는 시트로 열리므로, 화면을 고르면 시트를 닫습니다.
  const { isMobile, setOpenMobile } = useSidebar()
  return (
    <Sidebar>
      <SidebarHeader>
        <div className="flex items-center gap-2.5 px-2 py-2">
          <Brand />
        </div>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>운영</SidebarGroupLabel>
          <nav aria-label="화면">
            <SidebarGroupContent>
              <SidebarMenu>
                {navItems.map(({ id, label, icon: Icon }) => (
                  <SidebarMenuItem key={id}>
                    <SidebarMenuButton
                      isActive={tab === id}
                      aria-current={tab === id ? "page" : undefined}
                      onClick={() => {
                        onNavigate(id)
                        if (isMobile) setOpenMobile(false)
                      }}
                    >
                      <Icon />
                      <span>{label}</span>
                    </SidebarMenuButton>
                    {id === "jobs" && pending > 0 && (
                      <SidebarMenuBadge>{pending}</SidebarMenuBadge>
                    )}
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </nav>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter>
        <div className="flex items-center gap-2.5 rounded-lg border border-sidebar-border bg-background/60 p-2">
          <span
            aria-hidden="true"
            className="grid size-8 shrink-0 place-items-center rounded-full bg-sidebar-accent text-xs font-semibold uppercase text-sidebar-accent-foreground"
          >
            {(who || "?").slice(0, 1)}
          </span>
          <div className="grid min-w-0 flex-1 leading-tight">
            <span className="truncate text-sm font-medium">{who || "-"}</span>
            {now && (
              <span className="truncate text-xs text-muted-foreground">
                {new Date(now).toLocaleTimeString("ko-KR")} 갱신
              </span>
            )}
          </div>
          {onLogout && (
            <button
              type="button"
              onClick={onLogout}
              title="로그아웃"
              className="grid size-8 shrink-0 place-items-center rounded-md text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
            >
              <LogOutIcon className="size-4" />
              <span className="sr-only">로그아웃</span>
            </button>
          )}
        </div>
      </SidebarFooter>
    </Sidebar>
  )
}
