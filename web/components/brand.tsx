/** 로그인 화면, 사이드바, 모바일 헤더에서 사용하는 제품명입니다. */
export function Brand({ size = "md" }: { size?: "md" | "lg" }) {
  return (
    <span
      className={
        "font-bold tracking-tight " + (size === "lg" ? "text-2xl" : "text-lg")
      }
    >
      kpctl-linux
    </span>
  )
}
