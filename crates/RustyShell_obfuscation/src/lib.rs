#![no_std]
//! This crate is a thin wrapper around the [rusty_shell_obfuscation_proc_macro](). It provides reexport of crates (aes_gcm and hybrid_array) used inside code emitted by proc macros
//! 
//! It also provides an obfuscation feature which allows you to enable or disable encryption of strings passed to the **encrypt** and **encrypt_in_place macros**
//! 
//! It is part of the [RustyShell](https://github.com/LostAquilae/RustyShell) project.


// Reexport this crate so that users of this crate don't have to import it specifically
pub use aes_gcm;

// Reexport this crate so that users of this crate don't have to import it specifically
pub use hybrid_array;

pub use rusty_shell_obfuscation_proc_macro;

pub use rusty_shell_obfuscation_proc_macro::init_obfuscation;

/// Simple wrapper around the internal proc macro crate, that allows to be configured for encryption or not based on the obfuscation feature
#[cfg(feature = "obfuscation")]
#[macro_export]
macro_rules! encrypt {
    ($($tokentree:tt)*) => {
        rusty_shell_obfuscation::rusty_shell_obfuscation_proc_macro::encrypt!($($tokentree)*)
    };
}

/// Simple wrapper around the internal proc macro crate, that allows to be configured for encryption or not based on the obfuscation feature
#[cfg(not(feature = "obfuscation"))]
#[macro_export]
macro_rules! encrypt {
    ($($tokentree:tt)*) => {
        $($tokentree)*
    };
}

/// Simple wrapper around the internal proc macro crate, that allows to be configured for encryption or not based on the obfuscation feature
#[cfg(feature = "obfuscation")]
#[macro_export]
macro_rules! encrypt_in_place {
    ($($tokentree:tt)*) => {
        rusty_shell_obfuscation::rusty_shell_obfuscation_proc_macro::encrypt_in_place!($($tokentree)*)
    };
}

/// Simple wrapper around the internal proc macro crate, that allows to be configured for encryption or not based on the obfuscation feature
#[cfg(not(feature = "obfuscation"))]
#[macro_export]
macro_rules! encrypt_in_place {
    ($($tokentree:tt)*) => {
        $($tokentree)*
    };
}
