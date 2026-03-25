#![no_std]
#![no_main]
#![feature(ptr_cast_slice)]
// extern crate alloc;
// extern crate core;
// extern crate windows;
use core::{
    arch::asm,
    ffi::c_void,
    ptr::null_mut,
};

mod pe_types;
mod peb_types;

mod runtime_resolve;
use runtime_resolve::{get_dll_address, get_exported_function};
use wstr_literal::wstr;
// use windows::Win32::System::Threading::PEB;

/// Entry point of the code
///
/// This is a simple assembly routine, originally proposed
/// by @mattitestation here: https://github.com/mattifestation/PIC_Bindshell/blob/master/PIC_Bindshell/AdjustStack.asm
/// It makes the stack 16 bytes aligned prior to calling the "real" entry point, because on x64 targets, it is needed
/// so that the use of XMM registers don't crash. I removed the ret instruction, because as the asm in inside a
/// function definition, the Rust compiler will insert a ret at the end of the function
///
/// I used the no_mangle attribute so that the function name stay exactly as it is defined in order for the linker script to
/// find the symbol for the entry point (ENTRY in Linker.ld)
///
/// I also used the link_section attribute so that the function is in its own section, and use this section name in the linker script
/// to put this entry point at the start of the .text section (needed for shellcode, as execution will be given at the start of
/// the .text section)
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub extern "C" fn align_stack() -> i32 {
    unsafe {
        asm!(
            "push rsi",
            "mov rsi, rsp",
            "and rsp, 0x0FFFFFFFFFFFFFFF0",
            "sub rsp, 0x020",
            "call ExecutePayload",
            "mov rsp, rsi",
            "pop rsi"
        );
    }
    0
}

/// This is the actual 'entrypoint' of the code.
/// 
/// For now this function uses the get_dll_address and get_exported_function of the runtime_resolve module
/// to load User32.dll thanks to LoadLibraryA and then call MessageBoxA, doing all this shellcode compatible
#[unsafe(no_mangle)]
pub extern "C" fn ExecutePayload() {
    let kernel32_address = match get_dll_address(wstr!("kernel32.dll").as_ptr()) {
        Ok(address) => address,
        Err(error) => {
            return;
        }
    };

    let LoadLibraryA_address = match get_exported_function(kernel32_address, c"LoadLibraryA") {
        Ok(func_address) => func_address,
        Err(error) => {
            return
        }
    };

    let LoadLibraryA_func: fn(*const u8) -> *const c_void = unsafe { core::mem::transmute(LoadLibraryA_address) };
    let user32_address = LoadLibraryA_func(c"user32.dll".as_ptr().cast());

    let MessageBoxA_address = match get_exported_function(user32_address, c"MessageBoxA") {
        Ok(func_address) => func_address,
        Err(error) => {
            return;
        }
    };

    let MessageBoxA_func: fn(*mut c_void, *const u8, *const u8, u32) -> i32 = unsafe { core::mem::transmute(MessageBoxA_address) };
    let message_box_result = MessageBoxA_func(null_mut(), c"Hello World!".as_ptr().cast(), c"Wesh Alors".as_ptr().cast(), 0);

    return;
}
