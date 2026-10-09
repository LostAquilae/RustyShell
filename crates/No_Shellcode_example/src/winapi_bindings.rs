pub type LoadLibraryA = unsafe extern "system" fn(lplibfilename: PCSTR) -> HMODULE;

pub type MessageBoxA =
    unsafe extern "system" fn(hwnd: HWND, lptext: PCSTR, lpcaption: PCSTR, utype: u32) -> i32;

pub type HINSTANCE = *mut core::ffi::c_void;
pub type HMODULE = HINSTANCE;
pub type HWND = *mut core::ffi::c_void;
pub type PCSTR = *const u8;
