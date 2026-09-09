# PC-relative-vtable

Custom LLVM pass to make vtable relative

## Compiling

Compiling the project is actually pretty straight forward using cmake: 

```shell
mkdir build
cd build
cmake ..
make
```

LLVM version 23.1 needs to be installed on the system


## Testing

The build process gives you a .so that you can use with opt or directly with rust using the `-Z llvm-plugins=path/to/plugins` compilation flag, combined with `-C passes=relative-vtable` to enable the LLVM pass inside the rust compilation workflow. `--emit=llvm-ir` also needs to be enabled so that the resulting IR from the pass is actually used in the final binary (Otherwise, the pass is executed, but it doesn't seem to affect the final binary, I could not find out why).

## Credit

[Relative VTables for Rust](https://github.com/rust-lang/compiler-team/issues/903): Proposal for relative vtable ABI inside the Rust programming language. This LLVM pass actually only enables the solution proposed inside this issue, with minor changes

[LLVM Pass Skeleton](https://github.com/sampsyo/llvm-pass-skeleton): Repository showing an example of LLVM Pass