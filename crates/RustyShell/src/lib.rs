#![cfg_attr(feature = "shellcode", no_std)]
#![feature(ptr_cast_slice)]
#![allow(non_snake_case)]

#[cfg(feature = "shellcode")]
extern crate alloc;

#[cfg(feature = "shellcode")]
pub mod allocator;

mod peb_types;
pub mod runtime_resolve;
pub mod utils;
