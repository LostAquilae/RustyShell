//! This module provide useful function.
//!
//! Functions and structures defined here are useful functions
//! that can be used throughout the code.

use alloc::vec::Vec;

/// Function to resolve printf function at runtime and use it for debug purposes in shellcode target
///
/// This function loads msvcrt thanks to LoadLibraryA and get the printf exported function from it
/// then calls it for debug purposes. You can pass a &str or a String to this function, constructed using the
/// format! macro for example
#[cfg(feature = "debug")]
pub fn printf<T: Into<Vec<u8>>>(string: T) {
    use core::ffi::c_void;
    use alloc::ffi::CString;
    use crate::runtime_resolve::{get_exported_symbol, get_module_address};
    // Retrieving
    if let Ok(cstring) = CString::new(string) {
        if let Ok(kernel32_address) = get_module_address("kernel32.dll") {
            if let Ok(LoadLibraryA_address) = get_exported_symbol(kernel32_address, "LoadLibraryA") {
                let LoadLibraryA_func: extern "C" fn(*const u8) -> *const c_void = unsafe { core::mem::transmute(LoadLibraryA_address) };
                let msvcrt_address = LoadLibraryA_func(c"msvcrt.dll".as_ptr().cast());

                if !msvcrt_address.is_null() {
                    if let Ok(printf_address) = get_exported_symbol(msvcrt_address, "printf") {
                        let printf_func: extern "C" fn(...) -> i32 = unsafe { core::mem::transmute(printf_address) };
                        printf_func(cstring.as_ptr());
                        printf_func(c"\n".as_ptr());
                    }
                }
            }
        }
    }
}

/// Version of the printf function that does nothing. This is here to avoid compilation error when not compiling in debug mode
/// This actually comes with no overhead, because dead code elimination from the compiler will completely remove
#[cfg(not(feature = "debug"))]
pub fn printf<T: Into<Vec<u8>>>(_string: T) {

}