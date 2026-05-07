//! This module provide useful function.
//!
//! Functions and structures defined here are useful functions
//! that can be used throughout the code.

/// Macro to resolve printf function at runtime and use it for debug purposes in shellcode target
///
/// This macro loads msvcrt thanks to LoadLibraryA and get the printf exported function from it
/// then calls it for debug purposes. Since parameters are not formatted, you need to use it exactly like
/// the printf function in C, since they are passed completely unchanged to the function.
/// This needs to be a macro since there are no possible way to create a function with variadic parameters
/// in Rust.
#[cfg(feature = "debug")]
#[macro_export]
macro_rules! printf {
    ($($arg:tt)*) => {
        // Retrieving
        if let Ok(kernel32_address) = get_module_address("kernel32.dll") {
            if let Ok(LoadLibraryA_address) = get_exported_symbol(kernel32_address, "LoadLibraryA") {
                let LoadLibraryA_func: extern "C" fn(*const u8) -> *const c_void = unsafe { core::mem::transmute(LoadLibraryA_address) };
                let msvcrt_address = LoadLibraryA_func(c"msvcrt.dll".as_ptr().cast());

                if !msvcrt_address.is_null() {
                    if let Ok(printf_address) = get_exported_symbol(msvcrt_address, "printf") {
                        let printf_func: extern "C" fn(...) -> i32 = unsafe { core::mem::transmute(printf_address) };
                        printf_func($($arg)*);
                    }
                }
            }
        };
    };
}

/// Macro to resolve printf function at runtime and use it for debug purposes in shellcode target (In this not debug version of the crate, the macro simply does nothing)
#[cfg(not(feature = "debug"))]
#[macro_export]
macro_rules! printf {
    ($($arg:tt)*) => {};
}
