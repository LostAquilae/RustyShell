//! This crate propose a shellcode template for Rust to use Rust programming language to build shellcode compatible binary
//!
//! This entrypoint is the one actually used for shellcode

#![no_std]
#![no_main]
#![feature(ptr_cast_slice)]
#![allow(non_snake_case)]

use core::{arch::asm, ffi::c_void, ptr::null_mut};

extern crate alloc;
use alloc::format;
use alloc::vec::Vec;

mod peb_types;

mod allocator;

mod utils;
use utils::printf;

mod runtime_resolve;
use runtime_resolve::{get_exported_symbol, get_module_address};

mod winapi_bindings;

/// Entry point of the code
///
/// This is a simple assembly routine, originally proposed
/// by @mattitestation here: <https://github.com/mattifestation/PIC_Bindshell/blob/master/PIC_Bindshell/AdjustStack.asm>
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

#[inline(always)]
pub unsafe fn fn_cast<F>(raw: *const c_void, _proto: F) -> F {
    unsafe { core::mem::transmute_copy(&raw) }
}

/// This is the actual 'entrypoint' of the code.
///
/// This function contains example code of what is available right now as shellcode compatible
#[unsafe(no_mangle)]
pub extern "C" fn ExecutePayload() {
    // Calling LoadLibraryA to load user32.dll in memory
    let mut user32_address: *mut c_void = null_mut();
    resolve_call_winapi!(
        kernel32,
        LoadLibraryA,
        user32_address,
        c"user32.dll".as_ptr().cast()
    );

    // Checking return value of LoadLibraryA
    if user32_address.is_null() {
        printf("Couldn't retrieve user32 address via LoadLibraryA");
        return;
    }

    // Simple example of using a Vector for checking that the Global Allocator effectively works
    printf("Just before creating Vec");
    let mut vec = Vec::new();
    printf("Just after creating Vec");
    vec.push(1);
    printf("Just after pushing to Vec");
    vec.push(2);
    printf(format!(
        "Just after pushing to Vec second time, its value is: {:?}",
        vec
    ));

    // Example calling MessageBoxA
    let mut result_message_box: i32 = 0;
    call_winapi!(
        user32_address,
        MessageBoxA,
        result_message_box,
        null_mut(),
        c"Hello World!".as_ptr().cast(),
        c"Example".as_ptr().cast(),
        0
    );

    // Example showing the use of a printf with the format macro, which generates vtable that are relative thanks to LLVM Pass
    printf(format!(
        "The value returned by MessageBoxA is: {}",
        result_message_box
    ));

    return;
}
