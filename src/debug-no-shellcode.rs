//! This crate provides a full shellcode compatible loader to reflectively load any kind of PE
//!
//! It has 2 entrypoints, one with std loaded, for debug purposes and the other with
//! no std and an assembly entrypoint for shellcode

#![feature(ptr_cast_slice)]
#![allow(non_snake_case)]
mod runtime_resolve;
use runtime_resolve::{get_dll_address, get_exported_function};

mod pe_types;
mod peb_types;

use core::ffi::c_void;
use core::ptr::null_mut;
use std::error::Error;
use wstr_literal::wstr;

/// This function is simply here for debug purposes, when shellcode is not required to test some part of a code
///
/// For now this function uses the get_dll_address and get_exported_function of the runtime_resolve module
/// to load User32.dll thanks to LoadLibraryA and then call MessageBoxA, doing all this shellcode compatible
fn main() -> Result<(), Box<dyn Error>> {
    let kernel32_address = match get_dll_address(wstr!("kernel32.dll").as_ptr()) {
        Ok(address) => address,
        Err(error) => {
            println!("Couldn't retrieve kernel32.dll address, error: {:?}", error);
            return Err("Couldn't retrieve kernel32.dll address".into());
        }
    };

    println!("The address of kernel32.dll is: {:?}", kernel32_address);

    let LoadLibraryA_address = match get_exported_function(kernel32_address, c"LoadLibraryA") {
        Ok(func_address) => func_address,
        Err(error) => {
            println!("Couldn't retrieve LoadLibraryA address, error: {:?}", error);
            return Err("Couldn't retrieve LoadLibraryA address".into());
        }
    };

    println!(
        "The address of the LoadLibraryA function is: {:?}",
        LoadLibraryA_address
    );

    let LoadLibraryA_func: fn(*const u8) -> *const c_void =
        unsafe { core::mem::transmute(LoadLibraryA_address) };
    let user32_address = LoadLibraryA_func(c"user32.dll".as_ptr().cast());

    println!("The address of the User32.dll is: {:p}", user32_address);

    let MessageBoxA_address = match get_exported_function(user32_address, c"MessageBoxA") {
        Ok(func_address) => func_address,
        Err(error) => {
            println!("Couldn't retrieve MessageBoxA address, error: {:?}", error);
            return Err("Couldn't retrieve MessageBoxA address".into());
        }
    };

    let MessageBoxA_func: fn(*mut c_void, *const u8, *const u8, u32) -> i32 =
        unsafe { core::mem::transmute(MessageBoxA_address) };

    MessageBoxA_func(
        null_mut(),
        c"Hello World!".as_ptr().cast(),
        c"Wesh Alors".as_ptr().cast(),
        0,
    );

    Ok(())
}
