fn main() {
    // frontendDist（ui/）改动必须触发重编：Tauri 资源在编译期嵌入，
    // build.rs 未声明 rerun-if-changed 时改 UI 后 cargo 认为无变化——
    // exe 嵌入陈旧资源而磁盘文件是新的，症状=「界面是新的、功能是旧的」
    // （2026-10-17 主人点添加主机报 hf-name null 实测定性）。
    println!("cargo:rerun-if-changed=ui");
    tauri_build::build();
}
