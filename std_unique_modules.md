# STD unique modules

This is a collection of modules that are unique to the std, so that I can easily check wether a given type/struct/module is available in core or alloc feature

- backtrace
- env
- io
- os
- path
- process
- thread

List of macros that are not available elsewhere as well:

- dbg
- eprint
- eprintln
- is_x86_feature_detected
- print
- println
- thread_local

As we can see, there is not many module that are not available in core or alloc crate. We still have to confirm that everything could work in those crates as is in shellcode mode, but it is encouraging. Including the whole std seems to bring a lot of unuseful code that puts a lot of imports and relocations, and we can't have that. A good project would be to implement these modules and maccros inside a crate, like a std_shellcode crate, that we could use to have actually std features inside a shellcode compatible code in Rust. That would actually be amazing to have such a crate, meaning writing shellcode for windows would be actually kind of amazing.