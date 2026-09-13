//! This module provides different structures for working with the PEB on Windows
//!
//! These structures have been taken from the Windows crate, which is written by developers at microfost directly
//! to have maximum compatibility with Windows OS and respect the standard way of dealing with Windows.
//! Most of these structure are undocumented or semi-documented.

use core::ffi::c_void;
use windows_sys::Win32::{
    Foundation::UNICODE_STRING,
    System::{Kernel::LIST_ENTRY, WindowsProgramming::LDR_DATA_TABLE_ENTRY_0},
};

/// Structure that represents a module in the linked list of module inside an executable. We are redefining this sepcific structure
/// because we need to use BaseDllName field, which inside the windows crate is a reserved field with padding.
#[repr(C)]
#[allow(non_snake_case)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub Reserved1: [*mut c_void; 2],
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub Reserved2: [*mut c_void; 2],
    pub DllBase: *mut c_void,
    pub Reserved3: [*mut c_void; 2],
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub Reserved5: [*mut c_void; 2],
    pub Anonymous: LDR_DATA_TABLE_ENTRY_0,
    pub TimeDateStamp: u32,
}
