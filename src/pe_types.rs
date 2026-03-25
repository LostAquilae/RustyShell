//! This module provides different structures for working with PE files on Windows
//!
//! These structures have been taken from the Windows crate, which is written by developers at microfost directly
//! to have maximum compatibility with Windows OS and respect the standard way of dealing with Windows
//! You can checkout the PE documentation here: <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: IMAGE_DIRECTORY_ENTRY = IMAGE_DIRECTORY_ENTRY(0);

/// Structure representing the DOS header in PE files
#[repr(C, packed(2))]
#[derive(Clone, Copy, Debug)]
pub struct IMAGE_DOS_HEADER {
    /// The magic bytes 'MZ'
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    /// offset to the new PE headers
    pub e_lfanew: i32,
}

/// Structure representing the new Headers of PE file
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_NT_HEADERS64 {
    /// Magic bytes 'PE'
    pub Signature: u32,
    /// The COFF format header, which is also presents in full executables
    pub FileHeader: IMAGE_FILE_HEADER,
    /// The optional header containing useful informations about the executable
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

/// The COFF format header, which is also presents in full executables
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: IMAGE_FILE_MACHINE,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: IMAGE_FILE_CHARACTERISTICS,
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct IMAGE_FILE_MACHINE(pub u16);

#[allow(non_camel_case_types)]
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct IMAGE_FILE_CHARACTERISTICS(pub u16);

/// The optional header containing useful informations about the executable
#[allow(non_snake_case)]
#[repr(C, packed(4))]
#[derive(Clone, Copy)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: IMAGE_SUBSYSTEM,
    pub DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

/// Optional header Signature
#[allow(non_camel_case_types)]
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct IMAGE_OPTIONAL_HEADER_MAGIC(pub u16);

#[allow(non_camel_case_types)]
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct IMAGE_SUBSYSTEM(pub u16);

#[allow(non_camel_case_types)]
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct IMAGE_DLL_CHARACTERISTICS(pub u16);

/// Simple structure representing a data directory at the end of the optional header
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[allow(non_camel_case_types)]
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct IMAGE_DIRECTORY_ENTRY(pub u16);

/// Structure that represents the export directory to parse exported function of a module
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}
