use std::fs::{read_to_string, write};

fn main() {
    // Using windows bindgen to generate bindings for WINAPI we use
    windows_bindgen::Bindgen::new()
        .output("src/winapi_bindings.rs")
        .flat()
        .sys()
        .filters(["LoadLibraryA", "MessageBoxA"])
        .extern_fns()
        .write();

    // The windows bindgen crate generates 2 things for a WINAPI:
    // - The direct function you can call directly into your code
    // - The function pointer type that can be used as a function pointer
    //
    // Only the latter is of interest for us, since we are resolving WINAPI calls dynamically at runtime for shellcode purposes.
    // This small code only keep the type definitions and remove the functions
    let bindings_content =
        read_to_string("src/winapi_bindings.rs").expect("Error: Couldn't read bindings file");
    let filtered_bindings = bindings_content
        .lines()
        .filter(|line| !line.contains('{') && !line.contains('}') && !line.contains("pub fn"))
        .collect::<Vec<&str>>()
        .join("\n");
    write("src/winapi_bindings.rs", filtered_bindings)
        .expect("Error: Couldn't replace bindings content with filtered one");
}
