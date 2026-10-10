//! This crate propose a shellcode template for Rust to use Rust programming language to build shellcode compatible binary
//!
//! This entrypoint is the one used to test the code without shellcode
#![allow(non_snake_case)]

use core::ptr::null_mut;

use std::error::Error;

extern crate alloc;

use rusty_shell::{call_winapi, resolve_call_winapi};

mod winapi_bindings {
    include!(concat!(env!("OUT_DIR"), "/winapi_bindings.rs"));
}

/// This function is simply here for debug purposes, when shellcode is not required to test some part of a code
///
/// This function contains example code of what is available right now as shellcode compatible
fn main() -> Result<(), Box<dyn Error>> {
    println!("First instruction");
    // Calling LoadLibraryA to load user32.dll in memory
    let user32_address = resolve_call_winapi!(
        kernel32,
        LoadLibraryA,
        c"user32.dll".as_ptr().cast()
    )?;

    // Checking return value of LoadLibraryA
    if user32_address.is_null() {
        println!("Couldn't retrieve user32 address via LoadLibraryA");
        return Ok(());
    }

    // Simple example of using a Vector for checking that the Global Allocator effectively works
    println!("Just before creating Vec");
    let mut vec = Vec::new();
    println!("Just after creating Vec");
    vec.push(1);
    println!("Just after pushing to Vec");
    vec.push(2);
    println!(
        "Just after pushing to Vec second time, its value is: {:?}",
        vec
    );

    // Example calling MessageBoxA
    let result_message_box = call_winapi!(
        user32_address,
        MessageBoxA,
        null_mut(),
        c"Hello World!".as_ptr().cast(),
        c"Example".as_ptr().cast(),
        0
    )?;

    println!(
        "The value returned by MessageBoxA is: {}",
        result_message_box
    );

    Ok(())
}
