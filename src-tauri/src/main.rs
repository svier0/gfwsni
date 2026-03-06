#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    #[cfg(windows)]
    {
        let name = windows_sys::core::w!("gfwsni-single-instance");
        let mutex = unsafe {
            windows_sys::Win32::System::Threading::CreateMutexW(std::ptr::null(), 0, name)
        };
        if mutex.is_null() {
            eprintln!("创建互斥体失败");
        } else {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if err == windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS {
                unsafe {
                    windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
                        std::ptr::null_mut(),
                        windows_sys::core::w!("gfwsni 已在运行"),
                        windows_sys::core::w!("gfwsni"),
                        0,
                    )
                };
                return;
            }
        }
    }
    gfwsni_lib::run()
}
