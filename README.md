<p align="center">
    <img src="./rsc/RustyShell.png" width="700">
</p>

# RustyShell

Custom shellcode template in Rust

## Compiling

Compiling the project is actually pretty straight forward. I use the Cargo make crate, which you can install by running the following command: 

```shell
cargo install cargo-make
```

Then, you can use the cargo make with 3 different command:

```shell
cargo make windows_gnu_shellcode # Compiling as shellcode
cargo make windows_gnu_shellcode_debug # Compiling as shellcode with debug feature which makes the printf! macro print things to the console
cargo make windows_gnu_debug_no_shellcode # Compiling in debug mode not as shellcode
```

Compiling in debug mode will add traces to the executable execution by gating the println! behind shellcode feature, which is explicitly disabled by this target.

You also have the printf! macro you can use to print things while in shellcode, which will be made available with the debug shellcode target.

Compiling in shellcode mode actually gives you 2 output files: a .exe which is the full PE compiled and a .bin which is the .text section extracted, which gives you only the actual shellcode code that you can inject

## Contributing

To contribute to the project, certain rules must be followed in order to not break the shellcode compatibility:

- You should only rely on core and alloc crates for using rust standard library. The entry point for the shellcode target disables the std anyway so it won't compile if you include `use std` in your program. You can include `use core` or `use alloc` as you like though. For elements only present in the std crate, sorry but you cna't use them
- Crates in general may be used if they expose a `no-std` feature, which makes them usable in a no std environment, such as the shellcode target, but it may break shellcode anyway so tread carefully
- Every windows dependency should be resolved dynamically at runtime by using get_dll_address and get_exported_function functions. You can find them in the runtime_resolve module.
- You should avoid global and static variable. Depending on what you are doing with it, it might because of compiler optimization, but you should avoid completely using it

## Testing

For debug purposes, you now have the printf macro you can use. You should use it just like printf in C as it actually calls the printf implementation from msvcrt.dll. You can use C String literal combined with the as_ptr() method to provide the string to be formatted, along with values you want to format. You can also use println! macro if you gate behind condition compilation on shellcode feature not being enabled for the no shellcode debug target for easier printing.
