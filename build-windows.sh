#!/bin/bash

# OPTI_FLAGS="-Z unstable-options -C panic=immediate-abort -C link-arg=-Wl,-T./Linker.ld,--build-id=none -C link-arg=-nostdlib -C relocation-model=pic -C codegen-units=1 -C link-arg=-fno-ident -C link-arg=-fpack-struct=8 -C link-arg=-Wl,--gc-sections -C link-arg=-falign-jumps=1 -C link-arg=-w -C link-arg=-falign-labels=1 -C link-arg=-Wl,-s,--no-seh,--enable-stdcall-fixup -C link-arg=-Wl,--subsystem,console -C link-arg=-nostartfiles -C link-arg=-Wl,-ealign_stack"
OPTI_FLAGS="-Z unstable-options -C panic=immediate-abort -C link-arg=-nostdlib -C link-arg=-Wl,-T./Linker.ld"
# OPTI_FLAGS="-Z unstable-options -C panic=immediate-abort -C link-arg=-nostdlib -C link-arg=-Wl,-ealign_stack"
OPTI_ARGS="-Z build-std=core,panic_abort"

FIX_FLAGS="--config unstable.profile-rustflags=true --config profile.release.package.compiler_builtins.rustflags=['-Zshare-generics=off']"
RUSTFLAGS=$OPTI_FLAGS cargo build --bin HelLoader_shellcode --features shellcode --target x86_64-pc-windows-gnu --release $OPTI_ARGS

# RUSTFLAGS="-Z unstable-options -C panic=immediate-abort -C link-arg=-nostdlib -C link-arg=-Wl,-T./Linker.ld" cargo +nightly build --bin HelLoader_shellcode --features shellcode --target x86_64-pc-windows-gnu --release -Z build-std=core,panic_abort
# RUSTFLAGS="-Z build-std=core,panic_abort -Z unstable-options -C panic=immediate-abort -C link-arg=-nostdlib -C link-arg=-Wl,-T./Linker.ld" cargo +nightly build --bin HelLoader_shellcode --features shellcode --target x86_64-pc-windows-gnu --release