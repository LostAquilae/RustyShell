# RustyShell Obfuscation

Obfuscation crate for the RustyShell project

## ⚠️ Disclaimer

This project is intended **strictly for educational and authorized security research purposes only**.

By using this software, you agree that:

- You will only use it against systems, networks, or applications for which you have **explicit, written authorization** to test.
- You are solely responsible for ensuring your use complies with all applicable local, state, national, and international laws.
- The author(s) and contributors of this project **do not condone or support** any illegal or unauthorized use of this tool.
- This software is provided "AS IS", without warranty of any kind. The authors accept **no liability** for damage, data loss, legal consequences, or any other harm resulting from the use or misuse of this project.

Use of this tool against systems without prior mutual consent is illegal in most jurisdictions. **Unauthorized access to computer systems is a crime.**

## Macros

This crate allows you to do compile time encryption of string in your rust code, while being fully shellcode compatible. You have several macros you can use.

### init_obfuscation

You can call this macro like this:

```rust
    rusty_shell_obfuscation::init_obfuscation!();
```

You should call this at the root of your crate, in the main.rs or lib.rs. This will set up everything you need to use the other macros of this crate.

### encrypt

This macro allows you to encrypt a literal string and get a heap allocated string at runtime with the decrypted version of your literal string. You can use it like this:

```rust
    // Inside a variable
    let string: String = encrypt!("test_string");
    let cstring: CString = encrypt!(c"test_c_string");
    let concat_stringify = encrypt!(concat!(stringify!(test_concat), "_string"));
```

It works with string literals, C string literals and by using builtins macro like concat!, env!, include!, include_str!, stringify!, thanks to macro-string crate

### encrypt_in_place

This macro allows you to encrypt a literal string and get a stack allocated string literal.
Important! You need to specifically write the type in return. Internally, this crate implements wrapper around ArrayVec structure from the [arrayvec](https://crates.io/crates/arrayvec) crate, and it implements the Deref trait on it so that putting the '&' operator in front of the macro call coerce the return object to &str or &CStr depending on the type of literals you sent.
But you must specify the &str or &CStr type, otherwise, you will end up with a reference on these wrappers type, that are just here to coerce automatically to &str or &CStr.
Therefore, you can use it like this:

```rust
    // Inside a variable
    let string_literal: &str = &encrypt_in_place!("test_string");
    let c_string_literal: &CStr = &encrypt_in_place!(c"test_c_string");
    let concat_stringify_literal: &str = &encrypt_in_place!(concat!(stringify!(test_concat), "_string"));
```

You can use this when you don't want, or you can't, allocate on the heap.

## Conclusion

This macro is actually a wrapper around the internal rusty_shell_obfuscation_proc_macro. This is done like this because proc macro crate can't export other elements that procedural macro, and this wrapper crate actually reexports crates used inside the code emitted by the procedural macro in order to prevent you having to explicitly import them inside your Cargo.toml