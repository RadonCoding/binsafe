Code virtualizer for compiled 64-bit portable executables.

## How it works

### 1. Conversion

- **Parsing**: Input file is parsed using the [exe](https://crates.io/crates/exe/0.4.6) library.
- **Disassembly**: Using the [iced-x86](https://crates.io/crates/iced-x86) library the section containing the entry point is disassembled.
- **Conversion**: Instructions are converted into a bytecode format that the runtime can interpret.
- **Patching**: Instructions which were able to be converted are patched with **breakpoint** instructions `INT3` (`0xCC`).

### 2. Runtime

- **Execution**: In-case there are TLS callbacks the first callback is patched with the address of the runtime's entry point, otherwise the entry point is patched. The runtime entry point will call the original TLS callbacks and entry point after the initialization is completed.
- **Redirection**: An exception handler, which will catch the **breakpoints** is registered using [AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler).
- **Handling**: When a breakpoint is hit, the exception handler takes control and passes the [CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context) to the runtime.

## Usage

`cargo run --bin obfuscator -- <filename>`

## Contributing

1. Fork it
2. Create your branch (`git checkout -b my-change`)
3. Commit your changes (`git commit -m "changed something"`)
4. Push to the branch (`git push origin my-change`)
5. Create new pull request
