//! Custom shellcode Template in Rust
//!
//! This crate contains everything you need to code as a position-independent code (shellcode) in Rust

#![cfg_attr(feature = "shellcode", no_std)]
#![feature(ptr_cast_slice)]
#![allow(non_snake_case)]

#[cfg(feature = "shellcode")]
extern crate alloc;

#[cfg(feature = "shellcode")]
pub mod allocator;

mod peb_types;

#[cfg(feature = "shellcode")]
mod winapi_bindings;

pub mod runtime_resolve;
pub mod utils;
