//! This module provides different structures for working with the PEB on Windows
//!
//! These structures have been taken from the Windows crate, which is written by developers at microfost directly
//! to have maximum compatibility with Windows OS and respect the standard way of dealing with Windows.
//! Most of these structure are undocumented or semi-documented.

use core::ffi::c_void;

/// PEB Structure that represent the PEB found in every process of Windows
#[repr(C)]
#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug)]
pub struct PEB {
    pub Reserved1: [u8; 2],
    pub BeingDebugged: u8,
    pub Reserved2: [u8; 1],
    pub Reserved3: [*mut c_void; 2],
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub Reserved4: [*mut c_void; 3],
    pub AtlThunkSListPtr: *mut c_void,
    pub Reserved5: *mut c_void,
    pub Reserved6: u32,
    pub Reserved7: *mut c_void,
    pub Reserved8: u32,
    pub AtlThunkSListPtr32: u32,
    pub Reserved9: [*mut c_void; 45],
    pub Reserved10: [u8; 96],
    pub PostProcessInitRoutine: PPS_POST_PROCESS_INIT_ROUTINE,
    pub Reserved11: [u8; 128],
    pub Reserved12: [*mut c_void; 1],
    pub SessionId: u32,
}

/// Structure that represents a module in the linked list of module inside an executable
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

/// Internal structure defined by the Windows crate
#[repr(C)]
#[allow(non_snake_case)]
pub union LDR_DATA_TABLE_ENTRY_0 {
    pub CheckSum: u32,
    pub Reserved6: *mut c_void,
}

/// Internal function wrapped around an Option defined by the Windows crate
#[allow(non_camel_case_types)]
pub type PPS_POST_PROCESS_INIT_ROUTINE = Option<unsafe extern "system" fn()>;

/// Structure that contains user input such as the command line
#[repr(C)]
#[allow(non_snake_case)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub Reserved1: [u8; 16],
    pub Reserved2: [*mut c_void; 10],
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
}

/// Structure that represents UTF16 strings in Windows
#[repr(C)]
#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: PWSTR,
}

/// Simple type wrapper around a mutable UTF16 string
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct PWSTR(pub *mut u16);

/// Structure containing the list entries to iterate over the module list
#[repr(C)]
#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PEB_LDR_DATA {
    pub Reserved1: [u8; 8],
    pub Reserved2: [*mut c_void; 3],
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

/// Structure representing a list entry
#[repr(C)]
#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}
