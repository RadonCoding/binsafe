Code virtualizer for compiled 64-bit portable executables.

## How it works

### 1. Obfuscator

#### Source

- **Disassembly**: input is parsed with [exe](https://crates.io/crates/exe), and the section containing the entry point is disassembled into basic blocks via [iced-x86](https://crates.io/crates/iced-x86).
- **Mutation**: instructions are substituted with algebraically equivalent sequences using dead-flag analysis to preserve correctness.

#### Bytecode

- **Lifting**: instructions are translated into a stack-machine bytecode the runtime interprets.
- **Permutation**: operations are reordered through their data dependencies into a semantically equivalent sequence.
- **Encryption**: each block is chained to the tail of the previous so the sequence decrypts sequentially at runtime.

#### Embedding

- **Patching**: virtualized blocks are replaced with dispatch stubs that transfer control to the VM.

### 2. Runtime

#### State

- **TLS**: VM state lives in [Thread Local Storage](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-local-storage), so each thread runs the interpreter against its own registers and stacks.

#### Execution

- **Dispatch**: a stub transfers CPU state to the VM, which interprets the corresponding bytecode through indirect dispatch to handler functions.
- **Exceptions**: a vectored exception handler catches faults inside the VM region and reconstructs the CPU context for external handlers.

#### Protection

- **Attestation**: a leading sequence of VM-blocks runs anti-debug and integrity checks whose results feed into the decryption chain.

## Testing

The `tests` crate executes assembled bytecode through the VM against allocated executable memory.

- **Instructions**: each lifted instruction is run through the VM and the resulting register state is compared against the expected value.
- **Permutation**: each test block is exhausted through every valid scheduler ordering and compared against a reference run, so any divergence surfaces deterministically.

## Usage

`cargo run --release --bin obfuscator -- <filename> --virtualize --mutate`

## Contributing

1. Fork it
2. Create your branch (`git checkout -b my-change`)
3. Commit your changes (`git commit -m "changed something"`)
4. Push to the branch (`git push origin my-change`)
5. Create new pull request
