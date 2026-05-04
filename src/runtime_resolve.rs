use core::arch::asm;
use core::char;
use core::ffi::{CStr, c_void};
use core::error::Error;
use core::fmt::{Display, Formatter};

use crate::pe_types::*;
use crate::peb_types::*;

// use intrusive_collections::container_of;
// use widestring::U16String;

/// A simple error enum that gives information regarding the error that could occur in the runtime_resolve module
#[derive(Debug)]
pub enum RuntimeResolveErrors {
    NullPointer(* const c_void),
    CastError,
    ForwardedExportFunction(& 'static CStr),
    ExportNotFound(& 'static CStr),
    ModuleNotFound,
    Unknown,
}

impl Display for RuntimeResolveErrors {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            RuntimeResolveErrors::NullPointer(pointer) => write!(f, "Pointer sent as argument is null; here is its printed value: {:p}", pointer),
            RuntimeResolveErrors::CastError => write!(f, "Error while casting some value"),
            RuntimeResolveErrors::ForwardedExportFunction(function_name) => write!(f, "The function {:?} is an exported function, not implement yet", function_name),
            RuntimeResolveErrors::ExportNotFound(function_name) => write!(f, "The function {:?} couldn't be found", function_name),
            RuntimeResolveErrors::ModuleNotFound => write!(f, "The DLL couldn't be found"),
            RuntimeResolveErrors::Unknown => write!(f, "Unknown error"),
        }
    }
}

impl Error for RuntimeResolveErrors {}

/// Just a simple struct representing a WideString in Windows.
///
/// I use pointer for internal representation so that I can work on original values of strings inside the PEB for example
/// This is unsafe because it uses raw pointer, but when working with windows structures, you don't really have a choice
#[derive(Debug)]
pub struct WideString {
    /// Pointe toward the underlying string
    pub pointer: *const u16,
    /// Lenght of the string in characters, not bytes
    pub len: usize,
}

impl WideString {
    /// Construct a new WideString from a raw pointer
    pub fn new(pointer: *const u16) -> Result<Self, RuntimeResolveErrors> {
        // Checking for null pointer
        if pointer.is_null() {
            return Err(RuntimeResolveErrors::NullPointer(pointer.cast()));
        }

        // Constructing WideString structure
        let mut widestring = WideString {
            pointer: pointer,
            len: 0,
        };

        // Computing the length of the string
        let mut i = 0;
        while (unsafe { *pointer.add(i) } != 0) {
            i += 1;
        }

        // Returning the string with the computed length
        widestring.len = i;
        Ok(widestring)
    }
}

/// Implementing the PartielEq trait to compare widestring with UNICODE_STRING in Windows Structures
impl PartialEq for WideString {
    /// This equality will not take into account case, we will lowercase all letters
    fn eq(&self, other: &Self) -> bool {
        // Checking length equality before anything
        if self.len != other.len {
            return false;
        }

        // Make a copy of the pointers to offset them afterwards
        let pointer = self.pointer;
        let other_pointer = other.pointer;

        // Iterating over every character to check for equality
        for i in 0..self.len {
            // Here we transform every u16 into a character in rust, which allows us to use 'to_ascii_lowercase' afterwards
            let char1 = if let Some(char) = char::from_u32(u32::from(unsafe { *pointer.add(i) })) {
                char
            } else {
                return false;
            };

            let char2 =
                if let Some(char) = char::from_u32(u32::from(unsafe { *other_pointer.add(i) })) {
                    char
                } else {
                    return false;
                };

            // testing both character for equality, returning false if they are not equal
            if char1.to_ascii_lowercase() != char2.to_ascii_lowercase() {
                return false;
            }
        }

        return true;
    }
}

#[cfg(not(feature = "shellcode"))]
impl Display for WideString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // I'm allowing myself to use expect here, since this is to be used only for debug purposes, and ultimately, shouldn't fail, but if that's case, then is not important since it is for debug purposes
        let stringified_name = String::from_utf16(unsafe { core::slice::from_raw_parts(self.pointer, self.len) }).expect("Couldn't stringify the Widestring name");
        write!(f, "{}", stringified_name)
    }
}

/// Get the address of a DLL if it is loaded in memory
///
/// # Arguments
///
/// * `dll_name_pointer` - The pointer toward the UTF16 String of the DLL (required because DLL names inside the linked list of module are UNICODE_STRING).
///
/// # Return value
///
/// Returns a Result containing the raw pointer to the DLL or an error of type Errors
pub fn get_dll_address(dll_name_pointer: *const u16) -> Result<*const c_void, RuntimeResolveErrors> {
    // Constructing the WideString from the wide dll name
    let dll_name = WideString::new(dll_name_pointer)?;

    // Getting PEB address from gs register
    let peb_address: *const PEB;
    unsafe { asm!("mov {}, gs:0x60", out(reg) peb_address) };

    // Retrieving the list entry of in memory ordered modules to iterate over
    let ldr_data: *const PEB_LDR_DATA = unsafe { (*peb_address).Ldr };
    let head_entry: *const LIST_ENTRY = unsafe { &(*ldr_data).InMemoryOrderModuleList };
    let mut module_entry = unsafe { (*head_entry).Flink };

    // Iterating over the structures representing every loaded module inside the process
    while module_entry
        != unsafe { core::mem::transmute::<*const LIST_ENTRY, *mut LIST_ENTRY>(head_entry) }
    {
        // Since LIST_ENTRY structure gives us a pointer toward another list entry in another LDR_DATA_TABLE_ENTRY,
        // it actually gives us a pointer with an offset of 16 bytes, since the first element of the LDR_DATA_TABLE_ENTRY
        // is another list entry, which is the in load order list entry. Therefore, we need to substract 16 bytes to the pointer
        // given by the list_entry to point to the start of the LDR_DATA_TABLE_ENTRY structure
        let ldr_data_entry: *const LDR_DATA_TABLE_ENTRY =
            unsafe { core::mem::transmute(module_entry.byte_offset(-16)) };

        // Constructing the WideString from the BaseDllName field of the LDR_DATA_TABLE_ENTRY structure
        let current_dll_name = if let Ok(current_dll_name) =
            WideString::new(unsafe { (*ldr_data_entry).BaseDllName.Buffer.0 })
        {
            current_dll_name
        } else {
            module_entry = unsafe { (*module_entry).Flink };
            continue;
        };

        // Checking for equality of both strings, returning the DllBase field if this is the DLL we seek
        if current_dll_name == dll_name {
            #[cfg(not(feature = "shellcode"))]
            println!("Found dll {} at address: {:p}", dll_name, unsafe { (*ldr_data_entry).DllBase });
            return Ok(unsafe { (*ldr_data_entry).DllBase });
        }

        module_entry = unsafe { (*module_entry).Flink };
    }

    #[cfg(not(feature = "shellcode"))]
    if let Ok(dll_name_string) =
        String::from_utf16(unsafe { core::slice::from_raw_parts(dll_name.pointer, dll_name.len) })
    {
        println!("We couldn't find the dll named: {}", dll_name_string);
    } else {
        println!("Couldn't decode dll_name from raw array utf16 encoded");
    }

    Err(RuntimeResolveErrors::ModuleNotFound)
}

/// Get the address of a specific function inside a DLL
///
/// # Arguments
///
/// * `dll_address` - The pointer toward the DLL loaded in memory that exports the function.
/// * `function_name` - The name of the function to get the address to.
///
/// # Return value
///
/// Returns a Result containing the raw pointer to the function or an error of type Errors
pub fn get_exported_function(
    dll_address: *const c_void,
    function_name: &'static CStr,
) -> Result<*const c_void, RuntimeResolveErrors> {
    // Checking for null pointer
    if dll_address.is_null() {
        return Err(RuntimeResolveErrors::NullPointer(dll_address));
    }

    // Casting the pointer back to a reference
    let dos_header = unsafe { &*dll_address.cast::<IMAGE_DOS_HEADER>() };

    // Checking for the magic byte at the start of the DOS header
    if dos_header.e_magic != 0x5A4D {
        #[cfg(not(feature = "shellcode"))]
        println!("The pointer does not point to a DOS Header");
        return Err(RuntimeResolveErrors::Unknown);
    }

    // Computing the pointer toward the NT header and casting it as a reference
    let nt_header = unsafe {
        &*dll_address
            .byte_add(usize::try_from(dos_header.e_lfanew).map_err(|_| RuntimeResolveErrors::CastError)?)
            .cast::<IMAGE_NT_HEADERS64>()
    };

    // Checking for the magic byte at the start of the NT header
    if nt_header.Signature != 0x4550 {
        #[cfg(not(feature = "shellcode"))]
        println!("The pointer does not point to a NtHeader");
        return Err(RuntimeResolveErrors::Unknown);
    }

    // Retrieving the export table information
    let data_directories = &nt_header.OptionalHeader.DataDirectory;
    let image_export_directory = &data_directories[usize::from(IMAGE_DIRECTORY_ENTRY_EXPORT.0)];

    // Checking for export table existence
    if image_export_directory.Size == 0 || image_export_directory.VirtualAddress == 0 {
        #[cfg(not(feature = "shellcode"))]
        println!("No export directory inside the DLL");
        return Err(RuntimeResolveErrors::Unknown);
    }

    // Computing the pointer toward the export table
    let export_directory = unsafe {
        &*dll_address
            .byte_add(
                usize::try_from(image_export_directory.VirtualAddress)
                    .map_err(|_| RuntimeResolveErrors::CastError)?,
            )
            .cast::<IMAGE_EXPORT_DIRECTORY>()
    };

    // Casting to usize because i below needs to be usize for indexing in arrays
    let number_of_names =
        usize::try_from(export_directory.NumberOfNames).map_err(|_| RuntimeResolveErrors::CastError)?;

    // Constructing arrays into which we are going to index
    // We heavily use cast function from raw pointer, especially the cast_slice which is gated behind an unstable feature,
    // but so far, it works well and is actually a great idiomatic way of casting these pointers into arrays, for easier indexing later
    let name_table = unsafe {
        &*dll_address
            .byte_add(
                usize::try_from(export_directory.AddressOfNames).map_err(|_| RuntimeResolveErrors::CastError)?,
            )
            .cast::<u32>()
            .cast_slice(usize::try_from(number_of_names).map_err(|_| RuntimeResolveErrors::CastError)?)
    };
    let func_table = unsafe {
        &*dll_address
            .byte_add(
                usize::try_from(export_directory.AddressOfFunctions)
                    .map_err(|_| RuntimeResolveErrors::CastError)?,
            )
            .cast::<u32>()
            .cast_slice(usize::try_from(number_of_names).map_err(|_| RuntimeResolveErrors::CastError)?)
    };
    let ord_table = unsafe {
        &*dll_address
            .byte_add(
                usize::try_from(export_directory.AddressOfNameOrdinals)
                    .map_err(|_| RuntimeResolveErrors::CastError)?,
            )
            .cast::<u16>()
            .cast_slice(usize::try_from(number_of_names).map_err(|_| RuntimeResolveErrors::CastError)?)
    };

    // Looping through the name table to find the function we seek
    for i in 0..number_of_names {
        // Retrieving the name inside the export name table using previously gathered name_rva and casting to CStr for easier comparison
        // This is because the name_table actually only contains offsets from the DLL base toward string function names
        // That's why we have to compute the pointer again
        let cstr_name = unsafe {
            CStr::from_ptr(
                dll_address
                    .byte_add(usize::try_from(name_table[i]).map_err(|_| RuntimeResolveErrors::CastError)?)
                    .cast(),
            )
        };

        // Compare both strings, taking advantage of PartialEq implementation on CString
        if cstr_name == function_name {
            // If this is the function we seek, we retrieve the ordinal_rva for this function, which is at the same index than in the name_table
            let ordinal_rva = ord_table[i];

            // Using this ordinal, we can index inside the function_table to get the offset toward the actual function implementation
            let func_rva =
                func_table[usize::try_from(ordinal_rva).map_err(|_| RuntimeResolveErrors::CastError)?];

            // We check if this offset is outside the export directory, because if it is, it means the exported symbol is forwarded to another DLL
            if func_rva < image_export_directory.VirtualAddress
                || func_rva >= image_export_directory.VirtualAddress + image_export_directory.Size
            {
                #[cfg(not(feature = "shellcode"))]
                println!(
                    "Function {:?} found at address: {:p}",
                    function_name,
                    unsafe {
                        dll_address
                            .byte_add(usize::try_from(func_rva).map_err(|_| RuntimeResolveErrors::CastError)?)
                    }
                );

                return Ok(unsafe {
                    dll_address.byte_add(usize::try_from(func_rva).map_err(|_| RuntimeResolveErrors::CastError)?)
                });
            } else {
                // Returning an error for now, but implementation to handle this case will be coming
                return Err(RuntimeResolveErrors::ForwardedExportFunction(function_name));
            }
        }
    }

    #[cfg(not(feature = "shellcode"))]
    println!("Couldn't find the function: {:?}", function_name);

    Err(RuntimeResolveErrors::ExportNotFound(function_name))
}
