use regex::Regex;
use std::fs::{read_to_string, write};

fn main() {
    // Using windows bindgen to generate bindings for WINAPI we use
    windows_bindgen::Bindgen::new()
        .output("src/winapi_bindings.rs")
        .flat()
        .sys()
        .filters(["GetProcessHeap", "HeapAlloc", "HeapFree", "HeapReAlloc"])
        .extern_fns()
        .write();

    // The windows bindgen crate generates 2 things for a WINAPI:
    // - The direct function you can call directly into your code
    // - The function pointer type that can be used as a function pointer
    //
    // Only the latter is of interest for us, since we are resolving WINAPI calls dynamically at runtime for shellcode purposes.
    // This small code only keep the type definitions and remove the functions

    // Reading the generated bindings from file into a String
    let bindings_content =
        read_to_string("src/winapi_bindings.rs").expect("Error: Couldn't read bindings file");

    // Applying a regular expression to it to remove the function definitions
    let regex = Regex::new(r#"unsafe extern "system" \{[^}]*\}"#)
        .expect("Couldn't construct regex object from regex string");
    let filtered_bindings = regex.replace_all(&bindings_content, "").to_string();

    // Overwriting the winapi_bindings.rs content with the new filtered one
    write("src/winapi_bindings.rs", filtered_bindings)
        .expect("Error: Couldn't replace bindings content with filtered one");
}
