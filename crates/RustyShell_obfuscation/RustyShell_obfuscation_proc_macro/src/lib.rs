//! This crate provides proc macros to use for compile time encryption of strings. 
//! 
//! It is part of the [RustyShell](https://github.com/LostAquilae/RustyShell) project.

extern crate proc_macro;

use std::sync::LazyLock;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, Key, KeyInit},
};
use quote::quote;

use hybrid_array::sizes::U12;

use macro_string::MacroString;
use proc_macro::TokenStream;
use proc_macro2::Literal;
use proc_macro2::TokenStream as TokenStream2;
use syn::{Error, Lit, parse2};

static ENCRYPTION_KEY: LazyLock<Key<Aes256Gcm>> = LazyLock::new(|| Key::<Aes256Gcm>::generate());
static ENCRYPTION_NONCE: LazyLock<Nonce<U12>> = LazyLock::new(|| Nonce::<U12>::generate());

/// Macro to encrypt a string at compile time and emitting the code that decrypts at runtime
///
/// # Arguments
///
/// * `str` - Either a string literal, a C string literal or calls to macro supported by the [macro-string](https://crates.io/crates/macro-string) crate (concat!, env!, include!, include_str!, stringify!)
///
/// # Return value
///
/// A String whether the argument was a string literal or calls to macros, or a CString if the argument was a C string literal
#[proc_macro]
pub fn encrypt(stream: TokenStream) -> TokenStream {
    // Parse the string literal into a string
    let stream2: TokenStream2 = stream.into();

    // Parsing the inputs

    // This is first to test if the inputs is a literal, either a string literal or a C string literal
    let (string_to_encrypt, is_cstring) = if let Ok(lit) = parse2::<Lit>(stream2.clone()) {
        match lit {
            Lit::Str(lit_str) => (lit_str.value(), false),
            Lit::CStr(lit_cstr) => {
                match String::try_from(lit_cstr.value()) {
                    Ok(string) => {
                        (string, true)
                    }
                    Err(error) => return Error::new_spanned(
                    lit_cstr, format!("Couldn't convert this CStr into a String: {}", error)).to_compile_error().into(),
                }
            }
            _ => return Error::new_spanned(
                stream2, "Couldn't encrypt this string: Only string literals and C string literals are allowed").to_compile_error().into(),
        }
    // Here we check if the arguments are macro compiler builtins like concat!, env!, include!, include_str!, stringify!, and we eagerly evaluate them to use the result directly inside this macro
    } else if let Ok(macro_string) = parse2::<MacroString>(stream2.clone()) {
        match macro_string.eval() {
            Ok(string) => (string, false),
            Err(error) => {
                return Error::new_spanned(
                    stream2,
                    format!(
                        "Couldn't eagerly evaluate compiler builtin macro: {}",
                        error
                    ),
                )
                .to_compile_error()
                .into();
            }
        }
    } else {
        return Error::new_spanned(
            stream2,
            "The arguments were not a literal or compiler macro invocation",
        )
        .to_compile_error()
        .into();
    };

    // Setting up encryption
    let aes_key = &ENCRYPTION_KEY;
    let nonce = &ENCRYPTION_NONCE;
    let cypher = Aes256Gcm::new(&aes_key);

    // Encrypting the string
    let encrypted = match cypher.encrypt(nonce, string_to_encrypt.as_bytes()) {
        Ok(vec) => vec,
        Err(error) => {
            return Error::new_spanned(
                stream2,
                format!(
                    "Couldn't encrypt this string: {}, error: {}",
                    string_to_encrypt, error
                ),
            )
            .to_compile_error()
            .into();
        }
    };

    // Getting the Literal byte string of the encrypted version of the string to emit it inside the emitted code
    let literal_encrypted = Literal::byte_string(&encrypted);

    // Generating the code to emit
    // This is fine to call unsafe functions since this comes from literal strings
    let result = if is_cstring {
        // String literals must be utf-8 to compile, so from_utf8_unchecked should be safe
        quote! { unsafe { crate::obfuscation::CString::from_vec_unchecked(crate::obfuscation::decrypt(#literal_encrypted)) } }
    } else {
        // C String literals can't have interior null bytes to compile, so from_vec_unchecked should be safe
        quote! { unsafe { crate::obfuscation::String::from_utf8_unchecked(crate::obfuscation::decrypt(#literal_encrypted)) } }
    };

    result.into()
}

/// Macro to encrypt a string at compile time and emitting the code that decrypts at runtime
///
/// This macro works with stack allocated ArrayVec to remove the need for alloc crate
/// It is useful in environnement where you don't have alloc crate
///
/// This macro "returns" an ArrayVec that you can use to work on the decrypted string
///
/// # Arguments
///
/// * `str` - Either a string literal, a C string literal or calls to macro supported by the [macro-string](https://crates.io/crates/macro-string) crate (concat!, env!, include!, include_str!, stringify!)
///
/// # Returns
///
/// A &str whether the argument was a string literal or calls to macros, or a &CStr if the argument was a C string literal
#[proc_macro]
pub fn encrypt_in_place(stream: TokenStream) -> TokenStream {
    // Parse the string literal into a string
    let stream2: TokenStream2 = stream.into();

    // Parsing the inputs

    // This is first to test if the inputs is a literal, either a string literal or a C string literal
    // We simply retrieve the bytes we will encrypt. We take bytes with the nul terminator for a cstring literal so that the nul terminator is encrypted as well and is also retrieved when decrypting the string. You can then convert this back to a C string literal
    let (string_to_encrypt_bytes, is_cstring) = if let Ok(lit) = parse2::<Lit>(stream2.clone()) {
        match lit {
            Lit::Str(lit_str) => (lit_str.value().into_bytes(), false),
            Lit::CStr(lit_cstr) => (lit_cstr.value().into_bytes_with_nul(), true),
            _ => return Error::new_spanned(
                stream2, "Couldn't encrypt this string: Only string literals and C string literals are allowed").to_compile_error().into(),
        }
    // Here we check if the arguments are macro compiler builtins like concat!, env!, include!, include_str!, stringify!, and we eagerly evaluate them to use the result directly inside this macro
    } else if let Ok(macro_string) = parse2::<MacroString>(stream2.clone()) {
        match macro_string.eval() {
            Ok(string) => (string.into_bytes(), false),
            Err(error) => {
                return Error::new_spanned(
                    stream2,
                    format!(
                        "Couldn't eagerly evaluate compiler builtin macro: {}",
                        error
                    ),
                )
                .to_compile_error()
                .into();
            }
        }
    } else {
        return Error::new_spanned(
            stream2,
            "The arguments were not a literal or compiler macro invocation",
        )
        .to_compile_error()
        .into();
    };

    // Setting up encryption
    let aes_key = &ENCRYPTION_KEY;
    let nonce = &ENCRYPTION_NONCE;
    let cypher = Aes256Gcm::new(&aes_key);

    // Encrypting the string
    let encrypted = match cypher.encrypt(nonce, string_to_encrypt_bytes.as_slice()) {
        Ok(vec) => vec,
        Err(error) => {
            return Error::new_spanned(
                stream2,
                format!(
                    "Couldn't encrypt this string: {}, error: {}",
                    unsafe { str::from_utf8_unchecked(string_to_encrypt_bytes.as_slice()) },
                    error
                ),
            )
            .to_compile_error()
            .into();
        }
    };

    // Getting the size of the encrypted String
    // We need to get the size of the encrypted version because aes_gcm actually append some data to the encrypted version for authentication
    let len = encrypted.len();

    // Getting the Literal byte string of the encrypted version of the string to emit it inside the emitted code
    let literal_encrypted = Literal::byte_string(&encrypted);

    let result = if is_cstring {
        quote! {
            {
                let mut buffer: rusty_shell_obfuscation::aes_gcm::aead::arrayvec::ArrayVec<u8, #len> = rusty_shell_obfuscation::aes_gcm::aead::arrayvec::ArrayVec::<u8, #len>::new();
                buffer.try_extend_from_slice(#literal_encrypted).unwrap();
                crate::obfuscation::decrypt_in_place(&mut buffer);

                // This is fine to call from_bytes_with_nul_unchecked since this string comes from a C literal string at compile time that must bbe a valid C string (no interior nul byte and a terminating null byte)
                crate::obfuscation::ArrayVecCStrWrapper::from(buffer)
            }
        }
    } else {
        quote! {
            {
                let mut buffer: rusty_shell_obfuscation::aes_gcm::aead::arrayvec::ArrayVec<u8, #len> = rusty_shell_obfuscation::aes_gcm::aead::arrayvec::ArrayVec::<u8, #len>::new();
                buffer.try_extend_from_slice(#literal_encrypted).unwrap();
                crate::obfuscation::decrypt_in_place(&mut buffer);

                // This is fine to call from_utf8_unchecked since this string comes from a literal string at compile time that must be utf-8 to compile
                crate::obfuscation::ArrayVecStrWrapper::from(buffer)
            }
        }
    };

    result.into()
}

/// Macro to init the obfuscation process inside a crate
///
/// This macro ensure your crate has 2 static const variable, ENCRYPTION_KEY and ENCRYPTION_NONCE, which will end up inside .rdata section since they are read only, which is fine for shellcode
/// It also defines two functions: decrypt and decrypt_in_place
/// decrypt decrypts a string literal and yields a full String that lives on the stack
/// decrypt_in_place is for use when you don't have access to alloc crate, it decrypts a string in place, which was allocated on the stack thank to ArrayVec with encrypt_in_place
#[proc_macro]
pub fn init_obfuscation(_item: TokenStream) -> TokenStream {
    // Access both statics to initialize them
    let aes_key = &ENCRYPTION_KEY;
    let aes_nonce = &ENCRYPTION_NONCE;

    let result = quote! {
        // Emitting a module for obfuscation
        pub mod obfuscation {
            extern crate alloc;
            pub use alloc::{ffi::CString, string::String};
            use alloc::vec::Vec;
            use rusty_shell_obfuscation::aes_gcm::{aead::{Aead, Key, KeyInit, AeadInOut, arrayvec::ArrayVec, Buffer}, Aes256Gcm, Nonce};
            use rusty_shell_obfuscation::hybrid_array::sizes::U12;

            // Declaring encryption key and nonce as non mutable statics (end up in .rdata)
            static ENCRYPTION_KEY: [u8; 32] = [#(#aes_key),*];
            static ENCRYPTION_NONCE: [u8; 12] = [#(#aes_nonce),*];

            /// Struct that is thin wrapper around ArrayVec and that coerces automatically to &str thanks to the deref trait
            pub struct ArrayVecStrWrapper<const N: usize> {
                array_vec: ArrayVec<u8, N>
            }

            /// Implements Deref trait to automatically coerce to a &str
            impl<const N: usize> core::ops::Deref for ArrayVecStrWrapper<N> {
                type Target = core::primitive::str;

                fn deref(&self) -> &core::primitive::str {
                    // String literals must be utf-8 to compile, so from_utf8_unchecked should be safe
                    unsafe { core::str::from_utf8_unchecked(self.array_vec.as_slice())}
                }
            }

            /// Implements From to instantiate the type directly from an ArrayVec
            impl<const N: usize> From<ArrayVec<u8, N>> for ArrayVecStrWrapper<N> {
                fn from(array: ArrayVec<u8, N>) -> Self {
                    ArrayVecStrWrapper {
                        array_vec: array
                    }
                }
            }

            /// Struct that is thin wrapper around ArrayVec and that coerces automatically to &CStr thanks to the deref trait
            pub struct ArrayVecCStrWrapper<const N: usize> {
                array_vec: ArrayVec<u8, N>
            }

            /// Implements Deref trait to automatically coerce to a &CStr
            impl<const N: usize> core::ops::Deref for ArrayVecCStrWrapper<N> {
                type Target = core::ffi::CStr;

                fn deref(&self) -> &core::ffi::CStr {
                    // C String literals can't have interior null bytes to compile, so from_vec_unchecked should be safe
                    unsafe { core::ffi::CStr::from_bytes_with_nul_unchecked(self.array_vec.as_slice())}
                }
            }

            /// Implements From to instantiate the type directly from an ArrayVec
            impl<const N: usize> From<ArrayVec<u8, N>> for ArrayVecCStrWrapper<N> {
                fn from(array: ArrayVec<u8, N>) -> Self {
                    ArrayVecCStrWrapper {
                        array_vec: array
                    }
                }
            }

            // Declare decrypt function which yields a heap allocated String holding the decrypted version of encrypted string literal sent as argument
            pub fn decrypt(encrypted: &[u8]) -> Vec<u8> {
                let key: Key<Aes256Gcm> = ENCRYPTION_KEY.into();
                let nonce: Nonce::<U12> = ENCRYPTION_NONCE.into();
                let cypher = Aes256Gcm::new(&key);
                cypher.decrypt(&nonce, encrypted.as_ref()).unwrap()
            }

            // Declare decrypt_in_place function that takes a Buffer holding the encrypted string and decrypt it in place, without allocating anything
            pub fn decrypt_in_place(encrypted: &mut dyn Buffer) {
                let key: Key<Aes256Gcm> = ENCRYPTION_KEY.into();
                let nonce: Nonce::<U12> = ENCRYPTION_NONCE.into();
                let cypher = Aes256Gcm::new(&key);
                cypher.decrypt_in_place(&nonce, b"", encrypted).unwrap();
            }
        }

    };

    result.into()
}
