#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(e) = gfwsni_lib::run() {
        eprintln!("运行失败: {:?}", e);
        std::process::exit(1);
    }
}
