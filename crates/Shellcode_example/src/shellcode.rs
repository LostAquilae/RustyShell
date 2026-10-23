//! This crate propose a shellcode template for Rust to use Rust programming language to build shellcode compatible binary
//!
//! This entrypoint is the one actually used for shellcode

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(unused)]

use core::{arch::asm, ffi::c_void, ptr::null_mut};

extern crate alloc;
use alloc::format;
use alloc::vec::Vec;

use rusty_shell::{call_winapi, last_error_code, printf, resolve_call_winapi};

mod winapi_bindings {
    include!(concat!(env!("OUT_DIR"), "/winapi_bindings.rs"));
}

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
pub fn align_stack() -> i32 {
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
/// This function contains example code of what is available right now as shellcode compatible
#[unsafe(no_mangle)]
pub fn ExecutePayload() {
    // Calling LoadLibraryA to load user32.dll in memory
    let user32_address =
        match resolve_call_winapi!(kernel32, LoadLibraryA, c"user32.dll".as_ptr().cast()) {
            // This variant means the call to the WINAPI happened, we need to check the return value
            Ok(address) => {
                // If the address is NULL, then something went wrong, getting more info by calling last_error_code!
                if address.is_null() {
                    printf!("Couldn't retrieve user32.dll's address");
                    last_error_code!();
                    return;
                }

                address
            }
            // This variant means something went wrong while retrieving the WINAPI's address
            Err(error) => {
                printf!(
                    "Couldn't retrieve user32_address, error: {}",
                    error
                );
                return;
            }
        };

    // Simple example of using a Vector for checking that the Global Allocator effectively works
    printf!("Just before creating Vec");

    let mut vec = Vec::new();

    printf!("Just after creating Vec");

    vec.push(1);

    printf!("Just after pushing to Vec");

    vec.push(2);

    // Example showing the use of a printf with the format macro, which generates vtable that are relative thanks to LLVM Pass
    printf!(
        "Just after pushing to Vec second time, its value is: {:?}",
        vec
    );

    // Example calling MessageBoxA
    match call_winapi!(
        user32_address,
        MessageBoxA,
        null_mut(),
        c"Hello World!".as_ptr().cast(),
        c"Example".as_ptr().cast(),
        0
    ) {
        Ok(message_box_return_value) => {
            // Example showing the use of a printf with the format macro, which generates vtable that are relative thanks to LLVM Pass
            printf!(
                "The value returned by MessageBoxA is: {}",
                message_box_return_value
            );
        }
        Err(error) => {
            printf!("Couldn't call MessageBoxA, error: {}", error);
        }
    }

    return;
}
