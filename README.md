Code virtualizer for compiled 64-bit portable executables.

## How it works

### 1. Conversion

- **Parsing**: Input file is parsed using the [exe](https://crates.io/crates/exe) library.
- **Disassembly**: Using the [iced-x86](https://crates.io/crates/iced-x86) library the section containing the entry point is disassembled into basic blocks.
- **Conversion**: Instructions are converted into a bytecode format that the runtime can interpret.
- **Mutation**: Instructions can be substituted with algebraically equivalent sequences using dead flag analysis to preserve correctness.
- **Patching**: Virtualized blocks are replaced with dispatch stubs that transfer control to the VM.

### 2. Runtime

- **Dispatch**: When a virtualized block is executed, the dispatch stub transfers CPU state to the VM, which interprets the corresponding bytecode sequence.
- **Handling**: The VM maintains its own register state and shadow stack, executing bytecode through a interpreter with indirect dispatch to handler functions.
- **Anti-Debug**: Virtualized sequences are injected to specific VM blocks to hinder debugging.

## Usage

`cargo run --bin obfuscator -- <filename> --virtualize --mutate`

## Contributing

1. Fork it
2. Create your branch (`git checkout -b my-change`)
3. Commit your changes (`git commit -m "changed something"`)
4. Push to the branch (`git push origin my-change`)
5. Create new pull request
