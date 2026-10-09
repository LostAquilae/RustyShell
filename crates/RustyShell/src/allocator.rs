//! This module provide an implementation of a Global Allocator in a shellcode compatible way
//!
//! It creates a dummy structure onto which we will implement the trait
use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::null_mut,
};

use crate::call_winapi;
use crate::runtime_resolve::get_module_address;

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

        // Retrieving kernel32.dll address
        let kernel32_address = match get_module_address("kernel32.dll") {
            Ok(address) => address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Calling GetProcessHeap
        let process_heap_handle_result = call_winapi!(kernel32_address, GetProcessHeap);

        // Checking GetProcessHeap call return value
        let process_heap_handle = if let Ok(process_heap_handle) = process_heap_handle_result {
            // Checking return value for null pointer
            if process_heap_handle.is_null() {
                return null_mut();
            }
            process_heap_handle
        } else {
            return null_mut();
        };

        // Calling HeapAlloc function to allocate the requested memory block.
        // We Return directly the return value of HeapAlloc call. No need to check return value since return null is intended behavior to say allocation failed
        call_winapi!(kernel32_address, HeapAlloc, process_heap_handle, 0, size)
            .unwrap_or(null_mut())
            .cast()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // Retrieving kernel32.dll address
        let kernel32_address = match get_module_address("kernel32.dll") {
            Ok(address) => address,
            Err(_error) => {
                return;
            }
        };

        // Calling GetProcessHeap
        let process_heap_handle_result = call_winapi!(kernel32_address, GetProcessHeap);

        // Checking GetProcessHeap call return value
        let process_heap_handle = if let Ok(process_heap_handle) = process_heap_handle_result {
            // Checking return value for null pointer
            if process_heap_handle.is_null() {
                return;
            }
            process_heap_handle
        } else {
            return;
        };

        // Calling HeapFree to free the requested memory block
        let _ = call_winapi!(
            kernel32_address,
            HeapFree,
            process_heap_handle,
            0,
            ptr.cast()
        );
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // Checking the size given as argument is at least 1
        let size = layout.size();
        if size <= 0 {
            return null_mut();
        }

        // Retrieving kernel32.dll address
        let kernel32_address = match get_module_address("kernel32.dll") {
            Ok(address) => address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Calling GetProcessHeap
        let process_heap_handle_result = call_winapi!(kernel32_address, GetProcessHeap);

        // Checking GetProcessHeap call return value
        let process_heap_handle = if let Ok(process_heap_handle) = process_heap_handle_result {
            // Checking return value for null pointer
            if process_heap_handle.is_null() {
                return null_mut();
            }
            process_heap_handle
        } else {
            return null_mut();
        };

        // Calling HeapAlloc function to allocate the requested memory block, specifically indicating we want memory that is zero-initialized
        // Returning directly the return value of HeapAlloc call. No need to check return value since return null is intended behavior to say allocation failed
        call_winapi!(
            kernel32_address,
            HeapAlloc,
            process_heap_handle,
            HEAP_ZERO_MEMORY,
            size
        )
        .unwrap_or(null_mut())
        .cast()
    }

    unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
        // Checking the size given as argument is at least 1
        if new_size <= 0 {
            return null_mut();
        }

        // Retrieving kernel32.dll address
        let kernel32_address = match get_module_address("kernel32.dll") {
            Ok(address) => address,
            Err(_error) => {
                return null_mut();
            }
        };

        // Calling GetProcessHeap
        let process_heap_handle_result = call_winapi!(kernel32_address, GetProcessHeap);

        // Checking GetProcessHeap call return value
        let process_heap_handle = if let Ok(process_heap_handle) = process_heap_handle_result {
            // Checking return value for null pointer
            if process_heap_handle.is_null() {
                return null_mut();
            }
            process_heap_handle
        } else {
            return null_mut();
        };

        // Calling HeapReAlloc function to reallocate the requested memory block
        // Returning directly the return value of HeapAlloc call. No need to check return value since return null is intended behavior to say allocation failed
        call_winapi!(
            kernel32_address,
            HeapReAlloc,
            process_heap_handle,
            0,
            ptr.cast(),
            new_size
        )
        .unwrap_or(null_mut())
        .cast()
    }
}
