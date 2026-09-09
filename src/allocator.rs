//! This module provide an implementation of a Global Allocator in a shellcode compatible way
//!
//! It creates a dummy structure onto which we will implement the trait
use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_void,
    ptr::null_mut,
};

use crate::runtime_resolve::{get_exported_symbol, get_module_address};

pub const HEAP_ZERO_MEMORY: u32 = 0x00000008;

#[global_allocator]
static SHELLCODE_ALLOCATOR: ShellcodeCompatibleAllocator = ShellcodeCompatibleAllocator {};

/// Structure onto which we implement the GlobalAlloc trait so that we can benefit from this Global Allocator which is shellcode compatible
pub struct ShellcodeCompatibleAllocator {}

unsafe impl GlobalAlloc for ShellcodeCompatibleAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Retrieving kernel32.dll address
        let kernel32_address = match get_module_address("kernel32.dll") {
            Ok(address) => address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Retrieving GetProcessHeap address
        let GetProcessHeap_address = match get_exported_symbol(kernel32_address, "GetProcessHeap") {
            Ok(func_address) => func_address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Calling GetProcessHeap
        let GetProcessHeap_func: extern "C" fn() -> *mut c_void =
            unsafe { core::mem::transmute(GetProcessHeap_address) };
        let process_heap_handle = GetProcessHeap_func();

        // Checking return value for null pointer
        if process_heap_handle.is_null() {
            return null_mut();
        }

        // Retrieving HeapAlloc address
        let HeapAlloc_address = match get_exported_symbol(kernel32_address, "HeapAlloc") {
            Ok(func_address) => func_address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Checking the size given as argument is at least 1
        let size = layout.size();
        if size <= 0 {
            return null_mut();
        }

        // Calling HeapAlloc
        let HeapAlloc_func: extern "C" fn(*mut c_void, u32, usize) -> *mut c_void =
            unsafe { core::mem::transmute(HeapAlloc_address) };
        HeapAlloc_func(process_heap_handle, 0, size).cast()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // Retrieving kernel32.dll address
        let kernel32_address = match get_module_address("kernel32.dll") {
            Ok(address) => address,
            Err(_error) => {
                return;
            }
        };

        // Retrieving GetProcessHeap address
        let GetProcessHeap_address = match get_exported_symbol(kernel32_address, "GetProcessHeap") {
            Ok(func_address) => func_address,
            Err(_error) => {
                return;
            }
        };

        // Calling GetProcessHeap
        let GetProcessHeap_func: extern "C" fn() -> *mut c_void =
            unsafe { core::mem::transmute(GetProcessHeap_address) };
        let process_heap_handle = GetProcessHeap_func();

        // Checking return value for null pointer
        if process_heap_handle.is_null() {
            return;
        }

        // Retrieving HeapAlloc address
        let HeapFree_address = match get_exported_symbol(kernel32_address, "HeapFree") {
            Ok(func_address) => func_address,
            Err(_error) => {
                return;
            }
        };

        // Calling HeapAlloc
        let HeapFree_func: extern "C" fn(*mut c_void, u32, *const c_void) -> i32 =
            unsafe { core::mem::transmute(HeapFree_address) };
        HeapFree_func(process_heap_handle, 0, ptr.cast());
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // Retrieving kernel32.dll address
        let kernel32_address = match get_module_address("kernel32.dll") {
            Ok(address) => address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Retrieving GetProcessHeap address
        let GetProcessHeap_address = match get_exported_symbol(kernel32_address, "GetProcessHeap") {
            Ok(func_address) => func_address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Calling GetProcessHeap
        let GetProcessHeap_func: extern "C" fn() -> *mut c_void =
            unsafe { core::mem::transmute(GetProcessHeap_address) };
        let process_heap_handle = GetProcessHeap_func();

        // Checking return value for null pointer
        if process_heap_handle.is_null() {
            return null_mut();
        }

        // Retrieving HeapAlloc address
        let HeapAlloc_address = match get_exported_symbol(kernel32_address, "HeapAlloc") {
            Ok(func_address) => func_address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Checking the size given as argument is at least 1
        let size = layout.size();
        if size <= 0 {
            return null_mut();
        }

        // Calling HeapAlloc
        let HeapAlloc_func: extern "C" fn(*mut c_void, u32, usize) -> *mut c_void =
            unsafe { core::mem::transmute(HeapAlloc_address) };
        HeapAlloc_func(process_heap_handle, HEAP_ZERO_MEMORY, size).cast()
    }

    unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
        // Retrieving kernel32.dll address
        let kernel32_address = match get_module_address("kernel32.dll") {
            Ok(address) => address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Retrieving GetProcessHeap address
        let GetProcessHeap_address = match get_exported_symbol(kernel32_address, "GetProcessHeap") {
            Ok(func_address) => func_address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Calling GetProcessHeap
        let GetProcessHeap_func: extern "C" fn() -> *mut c_void =
            unsafe { core::mem::transmute(GetProcessHeap_address) };
        let process_heap_handle = GetProcessHeap_func();

        // Checking return value for null pointer
        if process_heap_handle.is_null() {
            return null_mut();
        }

        // Retrieving HeapAlloc address
        let HeapReAlloc_address = match get_exported_symbol(kernel32_address, "HeapReAlloc") {
            Ok(func_address) => func_address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Checking the size given as argument is at least 1
        if new_size <= 0 {
            return null_mut();
        }

        // Calling HeapAlloc
        let HeapReAlloc_func: extern "C" fn(*mut c_void, u32, *const c_void, usize) -> *mut c_void =
            unsafe { core::mem::transmute(HeapReAlloc_address) };
        HeapReAlloc_func(process_heap_handle, 0, ptr.cast(), new_size).cast()
    }
}
