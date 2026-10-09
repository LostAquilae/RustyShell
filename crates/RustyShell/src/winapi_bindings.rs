pub type GetProcessHeap = unsafe extern "system" fn() -> HANDLE;

pub type HeapAlloc = unsafe extern "system" fn(
    hheap: HANDLE,
    dwflags: u32,
    dwbytes: usize,
) -> *mut core::ffi::c_void;

pub type HeapFree =
    unsafe extern "system" fn(hheap: HANDLE, dwflags: u32, lpmem: *mut core::ffi::c_void) -> BOOL;

pub type HeapReAlloc = unsafe extern "system" fn(
    hheap: HANDLE,
    dwflags: u32,
    lpmem: *mut core::ffi::c_void,
    dwbytes: usize,
) -> *mut core::ffi::c_void;

pub type BOOL = i32;
pub type HANDLE = *mut core::ffi::c_void;
