Code virtualizer for compiled 64-bit portable executables.

## How it works

### 1. Obfuscator

#### Source

- **Disassembly**: input is parsed with [exe](https://crates.io/crates/exe), and the section containing the entry point is disassembled into basic blocks via [iced-x86](https://crates.io/crates/iced-x86).
- **Mutation**: instructions are substituted with algebraically equivalent sequences using dead-flag analysis to preserve correctness.

#### Bytecode

- **Lifting**: instructions are translated into a stack-machine bytecode the runtime interprets.
- **Permutation**: operations are reordered through their logical dependencies into a semantically equivalent sequence.
- **Scrambling**: operations are placed in a randomized physical layout connected by inserted jumps that follow their original execution order.
- **Mutation**: operations are rewritten into logically equivalent forms whose structure varies between builds.
- **Encryption**: immediate values in the bytecode are masked against a rolling key whose state advances between every immediate.
- **Chaining**: each block's decryption is seeded by the tail state of the previous block.

#### Embedding

- **Patching**: virtualized blocks are replaced with dispatch stubs that transfer control to the VM.

### 2. Runtime

#### State

- **Thread Contexts**: each thread maintains isolated VM state in [Thread Local Storage](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-local-storage), with its own registers and stacks.
- **Shadow Contexts**: nested execution contexts preserve parent state when the VM re-enters itself.

#### Execution

- **Dispatch**: a stub transfers CPU state to the VM, which interprets the corresponding bytecode through indirect dispatch to handler functions.
- **Exceptions**: a vectored exception handler catches faults inside the VM region and reconstructs the CPU context for external handlers.

#### Protection

- **Attestation**: anti-debug and integrity checks execute as VM bytecode and directly influence block decryption. Tampering or debugging silently corrupts execution through incorrect decryption rather than producing detectable failures.

## Testing

The `tests` crate spins up a frankenstein version of the VM, minimally instrumented to allow it to run for testing.

- **Instructions**: instruction is executed through the VM and the resulting context is compared against the CPU.
- **Permutation**: instruction sequence's dependency graph is exhaustively executed through the VM and verified.

## Usage

`cargo run --release --bin obfuscator -- <filename> --virtualization --mutation`

## Contributing

1. Fork it
2. Create your branch (`git checkout -b my-change`)
3. Commit your changes (`git commit -m "changed something"`)
4. Push to the branch (`git push origin my-change`)
5. Create new pull request
