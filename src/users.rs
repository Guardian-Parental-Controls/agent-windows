use std::collections::HashMap;

pub fn get_system_users_map() -> HashMap<u32, String> {
    #[cfg(target_os = "windows")]
    {
        crate::windows_service::policy::get_windows_users_map()
    }
    #[cfg(not(target_os = "windows"))]
    {
        HashMap::new()
    }
}
