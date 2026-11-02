//! This module provide an implementation of a Global Allocator in a shellcode compatible way
//!
//! It creates a dummy structure onto which we will implement the trait
use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_void,
    ptr::null_mut,
};

use crate::runtime_resolve::{get_exported_symbol, get_module_address};
use crate::rusty_shell_obfuscation::encrypt_in_place;

use windows_sys::Win32::System::Memory::HEAP_ZERO_MEMORY;

#[global_allocator]
static SHELLCODE_ALLOCATOR: ShellcodeCompatibleAllocator = ShellcodeCompatibleAllocator {};

/// Structure onto which we implement the GlobalAlloc trait so that we can benefit from this Global Allocator which is shellcode compatible
pub struct ShellcodeCompatibleAllocator {}

unsafe impl GlobalAlloc for ShellcodeCompatibleAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Checking the size given as argument is at least 1
        let size = layout.size();
        if size <= 0 {
            return null_mut();
        }

        // let kernel32_name = encrypt_in_place!("kernel32.dll");
        let kernel32_address = match get_module_address(&encrypt_in_place!("kernel32.dll")) {
            Ok(address) => address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Retrieving GetProcessHeap's address
        // let get_process_heap_name = encrypt_in_place!("GetProcessHeap");
        let GetProcessHeap_address =
            match get_exported_symbol(kernel32_address, &encrypt_in_place!("GetProcessHeap")) {
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
        // let heap_alloc_name = encrypt_in_place!("HeapAlloc");
        let HeapAlloc_address =
            match get_exported_symbol(kernel32_address, &encrypt_in_place!("HeapAlloc")) {
                Ok(func_address) => func_address,
                Err(_error) => {
                    return null_mut();
                }
            };

        // Calling HeapAlloc function to allocate the requested memory block.
        // We Return directly the return value of HeapAlloc call. No need to check return value since return null is intended behavior to say allocation failed
        let HeapAlloc_func: extern "C" fn(*mut c_void, u32, usize) -> *mut c_void =
            unsafe { core::mem::transmute(HeapAlloc_address) };
        HeapAlloc_func(process_heap_handle, 0, size).cast()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // Retrieving kernel32.dll address
        // let kernel32_name = encrypt_in_place!("kernel32.dll");
        let kernel32_address = match get_module_address(&encrypt_in_place!("kernel32.dll")) {
            Ok(address) => address,
            Err(_error) => {
                return;
            }
        };

        // Retrieving GetProcessHeap's address
        // let get_process_heap_name = encrypt_in_place!("GetProcessHeap");
        let GetProcessHeap_address =
            match get_exported_symbol(kernel32_address, &encrypt_in_place!("GetProcessHeap")) {
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
        // let heap_free_name = encrypt_in_place!("HeapFree");
        let HeapFree_address =
            match get_exported_symbol(kernel32_address, &encrypt_in_place!("HeapFree")) {
                Ok(func_address) => func_address,
                Err(_error) => {
                    return;
                }
            };

        // Calling HeapFree to free the requested memory block
        let HeapFree_func: extern "C" fn(*mut c_void, u32, *const c_void) -> i32 =
            unsafe { core::mem::transmute(HeapFree_address) };
        HeapFree_func(process_heap_handle, 0, ptr.cast());
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // Checking the size given as argument is at least 1
        let size = layout.size();
        if size <= 0 {
            return null_mut();
        }

        // Retrieving kernel32.dll address
        // let kernel32_name = encrypt_in_place!("kernel32.dll");
        let kernel32_address = match get_module_address(&encrypt_in_place!("kernel32.dll")) {
            Ok(address) => address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Retrieving GetProcessHeap's address
        // let get_process_heap_name = encrypt_in_place!("GetProcessHeap");
        let GetProcessHeap_address =
            match get_exported_symbol(kernel32_address, &encrypt_in_place!("GetProcessHeap")) {
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
        // let heap_alloc_name = encrypt_in_place!("HeapAlloc");
        let HeapAlloc_address =
            match get_exported_symbol(kernel32_address, &encrypt_in_place!("HeapAlloc")) {
                Ok(func_address) => func_address,
                Err(_error) => {
                    return null_mut();
                }
            };

        // Calling HeapAlloc function to allocate the requested memory block, specifically indicating we want memory that is zero-initialized
        // Returning directly the return value of HeapAlloc call. No need to check return value since return null is intended behavior to say allocation failed
        let HeapAlloc_func: extern "C" fn(*mut c_void, u32, usize) -> *mut c_void =
            unsafe { core::mem::transmute(HeapAlloc_address) };
        HeapAlloc_func(process_heap_handle, HEAP_ZERO_MEMORY, size).cast()
    }

    unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
        // Checking the size given as argument is at least 1
        if new_size <= 0 {
            return null_mut();
        }

        // Retrieving kernel32.dll address
        // let kernel32_name = encrypt_in_place!("kernel32.dll");
        let kernel32_address = match get_module_address(&encrypt_in_place!("kernel32.dll")) {
            Ok(address) => address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Retrieving GetProcessHeap's address
        // let get_process_heap_name = encrypt_in_place!("GetProcessHeap");
        let GetProcessHeap_address =
            match get_exported_symbol(kernel32_address, &encrypt_in_place!("GetProcessHeap")) {
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
        let HeapReAlloc_address =
            match get_exported_symbol(kernel32_address, &encrypt_in_place!("HeapReAlloc")) {
                Ok(func_address) => func_address,
                Err(_error) => {
                    return null_mut();
                }
            };

        // Calling HeapReAlloc function to reallocate the requested memory block
        // Returning directly the return value of HeapAlloc call. No need to check return value since return null is intended behavior to say allocation failed
        let HeapReAlloc_func: extern "C" fn(*mut c_void, u32, *const c_void, usize) -> *mut c_void =
            unsafe { core::mem::transmute(HeapReAlloc_address) };
        HeapReAlloc_func(process_heap_handle, 0, ptr.cast(), new_size).cast()
    }
}
