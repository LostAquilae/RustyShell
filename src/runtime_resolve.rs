use core::arch::asm;
use core::convert::TryFrom;
use core::error::Error;
use core::ffi::{CStr, c_void};
use core::fmt::{Display, Formatter};

use widestring::U16Str;

use crate::pe_types::*;
use crate::peb_types::*;

/// A simple error enum that gives information regarding the error that could occur in the runtime_resolve module.
///
/// Using 'static lifetime is okay for now since we use string literals, which will reside in .rdata section, which
/// is appended at the end of the .text section.
#[derive(Debug)]
pub enum RuntimeResolveErrors {
    /// Some pointer sent as argument is null
    NullPointer(*const c_void),
    /// Some casting operation went wrong
    CastError,
    /// The export function was not found
    ExportNotFound(&'static str),
    /// The module was not found in the process memory
    ModuleNotFound(&'static str),
    /// Any other kind of errors
    Unknown,
}

/// Implementing display on RuntimeResolveErrors, displaying information about the error that occurred
impl Display for RuntimeResolveErrors {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            RuntimeResolveErrors::NullPointer(pointer) => write!(
                f,
                "Pointer sent as argument is null; here is its printed value: {:p}",
                pointer
            ),
            RuntimeResolveErrors::CastError => write!(f, "Error while casting some value"),
            RuntimeResolveErrors::ExportNotFound(symbol_name) => {
                write!(f, "The function {:?} couldn't be found", symbol_name)
            }
            RuntimeResolveErrors::ModuleNotFound(module_name) => {
                write!(f, "The DLL {} couldn't be found", module_name)
            }
            RuntimeResolveErrors::Unknown => write!(f, "Unknown error"),
        }
    }
}

impl Error for RuntimeResolveErrors {}

/// Just a simple struct representing a Dll name as WideString
///
/// I use the U16CStr type from widestring crate to handle widestring manipulation
/// This type exists so that we can implement PartialEq<&str> on U16CStr
#[derive(Debug)]
pub struct ModuleWideString<'a>(&'a U16Str);

impl ModuleWideString<'_> {
    /// Construct a new DLlWideString from a raw pointer and the length
    pub fn from_ptr(pointer: *const u16, len: usize) -> Self {
        ModuleWideString(unsafe { U16Str::from_ptr(pointer, len) })
    }
}

/// Used to compare string literals with UNICODE_STRING in Windows
///
/// This equality is designed to work exactly like
/// in LoadLibraryA: <https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya#parameters>
/// where you can pass a module name without its extension, like kernel32 to search for kernel32.dll
/// It is also case insensitive
impl PartialEq<&str> for ModuleWideString<'_> {
    fn eq(&self, other: &&str) -> bool {
        // Retrieving the number of chars for each string
        let self_number_of_chars = self.0.chars_lossy().count();
        let other_number_of_chars = other.chars().count();

        // If the str passed as argument is longer than the dll name, we immediately
        // return false because there is no case where strings would be considered equal here
        // (Reciprocal is not true since string literal might be shorter and still considered equal because of the missing file extension)
        if other_number_of_chars > self_number_of_chars {
            return false;
        }

        // I use chars_lossy here because I assume that dll names inside the peb will always contains valid utf16 characters
        // I iterate over chars of the literal string as I am now sure that the DllWideString contains at least the same number of chars
        // I manually iterate over the iterator of self so that I can iterate one more time after the loop ended
        let mut self_iter = self.0.chars_lossy();
        for other_char in other.chars() {
            let self_char = if let Some(char) = self_iter.next() {
                char
            } else {
                return false;
            };

            if self_char.to_ascii_lowercase() != other_char.to_ascii_lowercase() {
                return false;
            }
        }

        // At this point, we finished iterating over the string literal passed as argument
        // Now, there is 2 cases possible for equality to be true:
        // - The DllWideString is also terminated, in this case, string would be indeed considered equal, as they have the exact same characters
        // - The DllWideString is not terminated, but its next character is '.', which in a module name in windows would be the extension .dll or .exe
        if let Some(char) = self_iter.next() {
            // Checking if the character is '.'
            if char == '.' {
                return true;
            } else {
                return false;
            }
        // If the iterator returned None because string is terminated, we also return true here
        } else {
            return true;
        }
    }
}

/// Just implementing Display on ModuleWideString, deferring work to the display() method of the inner U16Str
impl Display for ModuleWideString<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

/// Get the address of a DLL if it is loaded in memory
///
/// # Arguments
///
/// * `module_name` - The string literal containing the module name to search for
///
/// # Return value
///
/// Returns a Result containing the raw pointer to the DLL or an error of type Errors
pub fn get_module_address(
    module_name: &'static str,
) -> Result<*const c_void, RuntimeResolveErrors> {
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
        // is another list entry, which is the in load order list entry. Therefore, we need to subtract 16 bytes to the pointer
        // given by the list_entry to point to the start of the LDR_DATA_TABLE_ENTRY structure
        let ldr_data_entry: *const LDR_DATA_TABLE_ENTRY =
            unsafe { core::mem::transmute(module_entry.byte_offset(-16)) };

        // Constructing the WideString from the BaseDllName field of the LDR_DATA_TABLE_ENTRY structure.
        // We divide the Length member of the UNICODE_STRING by 2 since it is in bytes and we need it in characters,
        // assuming that every character in the WideString UTF-16 encoded will take only 16 bytes
        // since it is only module names on windows that should only have ASCII character
        let current_dll_name =
            ModuleWideString::from_ptr(unsafe { (*ldr_data_entry).BaseDllName.Buffer.0 }, unsafe {
                usize::from((*ldr_data_entry).BaseDllName.Length / 2)
            });

        // Checking for equality of both strings, returning the DllBase field if this is the DLL we seek
        if current_dll_name == module_name {
            #[cfg(not(feature = "shellcode"))]
            println!("Found dll {} at address: {:p}", module_name, unsafe {
                (*ldr_data_entry).DllBase
            });

            // Retrieving the pointer and checking for it to be non null
            let dll_base = unsafe { (*ldr_data_entry).DllBase };
            if dll_base.is_null() {
                return Err(RuntimeResolveErrors::ModuleNotFound(module_name));
            } else {
                return Ok(unsafe { (*ldr_data_entry).DllBase });
            }
        }

        // Updating the module_entry, advancing in the linked list
        module_entry = unsafe { (*module_entry).Flink };
    }

    #[cfg(not(feature = "shellcode"))]
    println!("We couldn't find the dll named: {}", module_name);

    Err(RuntimeResolveErrors::ModuleNotFound(module_name))
}

/// Get the address of a specific symbol inside a DLL
///
/// # Arguments
///
/// * `module_address` - The pointer toward the DLL loaded in memory that exports the symbol.
/// * `symbol_name` - The name of the symbol to get the address to.
///
/// # Return value
///
/// Returns a Result containing the raw pointer to the symbol or an error of type Errors
pub fn get_exported_symbol(
    module_address: *const c_void,
    symbol_name: &'static str,
) -> Result<*const c_void, RuntimeResolveErrors> {
    // Checking for null pointer
    if module_address.is_null() {
        return Err(RuntimeResolveErrors::NullPointer(module_address));
    }

    // Casting the pointer back to a reference
    let dos_header = unsafe { &*module_address.cast::<IMAGE_DOS_HEADER>() };

    // Checking for the magic byte at the start of the DOS header
    if dos_header.e_magic != 0x5A4D {
        #[cfg(not(feature = "shellcode"))]
        println!("The pointer does not point to a DOS Header");
        return Err(RuntimeResolveErrors::Unknown);
    }

    // Computing the pointer toward the NT header and casting it as a reference
    let nt_header = unsafe {
        &*module_address
            .byte_add(
                usize::try_from(dos_header.e_lfanew)
                    .map_err(|_| RuntimeResolveErrors::CastError)?,
            )
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
        &*module_address
            .byte_add(
                usize::try_from(image_export_directory.VirtualAddress)
                    .map_err(|_| RuntimeResolveErrors::CastError)?,
            )
            .cast::<IMAGE_EXPORT_DIRECTORY>()
    };

    // Casting to usize because i below needs to be usize for indexing in arrays
    let number_of_names = usize::try_from(export_directory.NumberOfNames)
        .map_err(|_| RuntimeResolveErrors::CastError)?;

    // Constructing arrays into which we are going to index
    // We heavily use cast function from raw pointer, especially the cast_slice which is gated behind an unstable feature,
    // but so far, it works well and is actually a great idiomatic way of casting these pointers into arrays, for easier indexing later
    let name_table = unsafe {
        &*module_address
            .byte_add(
                usize::try_from(export_directory.AddressOfNames)
                    .map_err(|_| RuntimeResolveErrors::CastError)?,
            )
            .cast::<u32>()
            .cast_slice(
                usize::try_from(number_of_names).map_err(|_| RuntimeResolveErrors::CastError)?,
            )
    };
    let symbol_table = unsafe {
        &*module_address
            .byte_add(
                usize::try_from(export_directory.AddressOfFunctions)
                    .map_err(|_| RuntimeResolveErrors::CastError)?,
            )
            .cast::<u32>()
            .cast_slice(
                usize::try_from(number_of_names).map_err(|_| RuntimeResolveErrors::CastError)?,
            )
    };
    let ord_table = unsafe {
        &*module_address
            .byte_add(
                usize::try_from(export_directory.AddressOfNameOrdinals)
                    .map_err(|_| RuntimeResolveErrors::CastError)?,
            )
            .cast::<u16>()
            .cast_slice(
                usize::try_from(number_of_names).map_err(|_| RuntimeResolveErrors::CastError)?,
            )
    };

    // Looping through the name table to find the function we seek
    for i in 0..number_of_names {
        // Retrieving the name inside the export name table using previously gathered name_rva and casting to &str for easier comparison
        // This is because the name_table actually only contains offsets from the DLL base toward string function names
        // That's why we have to compute the pointer again
        let cstr_name = unsafe {
            CStr::from_ptr(
                module_address
                    .byte_add(
                        usize::try_from(name_table[i])
                            .map_err(|_| RuntimeResolveErrors::CastError)?,
                    )
                    .cast(),
            )
        }
        .to_str()
        .map_err(|_| RuntimeResolveErrors::CastError)?;

        // Compare both strings thanks to PartialEq implementation on &str
        if cstr_name == symbol_name {
            // If this is the function we seek, we retrieve the ordinal_rva for this function, which is at the same index than in the name_table
            let ordinal_rva = ord_table[i];

            // Using this ordinal, we can index inside the function_table to get the offset toward the actual function implementation
            let symbol_rva = symbol_table
                [usize::try_from(ordinal_rva).map_err(|_| RuntimeResolveErrors::CastError)?];

            // We check if this offset is outside the export directory, because if it is, it means the exported symbol is forwarded to another DLL
            if symbol_rva < image_export_directory.VirtualAddress
                || symbol_rva >= image_export_directory.VirtualAddress + image_export_directory.Size
            {
                #[cfg(not(feature = "shellcode"))]
                println!(
                    "Function {:?} found at address: {:p}",
                    symbol_name,
                    unsafe {
                        module_address.byte_add(
                            usize::try_from(symbol_rva)
                                .map_err(|_| RuntimeResolveErrors::CastError)?,
                        )
                    }
                );

                // Returning the computed absolute address of the symbol in memory
                return Ok(unsafe {
                    module_address.byte_add(
                        usize::try_from(symbol_rva).map_err(|_| RuntimeResolveErrors::CastError)?,
                    )
                });
            } else {
                // Retrieving the forwarded function strings, split between 2 strings at the first '.' appearance.
                let (module_name, forwarded_symbol_name) = unsafe {
                    CStr::from_ptr(
                        module_address
                            .byte_add(
                                usize::try_from(symbol_rva)
                                    .map_err(|_| RuntimeResolveErrors::CastError)?,
                            )
                            .cast(),
                    )
                }
                .to_str()
                .map_err(|_| RuntimeResolveErrors::CastError)?
                .split_once('.')
                .ok_or(RuntimeResolveErrors::CastError)?;

                // Retrieving the address of the module exporting the forwarded symbol export
                let module_address = get_module_address(module_name)?;

                // Recursive call
                return get_exported_symbol(module_address, forwarded_symbol_name);
            }
        }
    }

    #[cfg(not(feature = "shellcode"))]
    println!("Couldn't find the function: {:?}", symbol_name);

    Err(RuntimeResolveErrors::ExportNotFound(symbol_name))
}
