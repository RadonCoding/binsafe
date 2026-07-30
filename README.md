![](example.gif)

Obfuscator for compiled 64-bit portable executables.

## How it works

### 1. Obfuscator

#### Analysis
- **Disassembly**: the binary's code section is disassembled and partitioned into basic blocks by tracing all reachable control flow, including switch tables and exception handler boundaries.

#### Virtualization
- **Lifting**: instructions are translated into a custom stack-machine bytecode that the runtime interprets.
- **Peephole**: bytecode is scanned in multiple passes to simplify sequences and collapse redundant operations.
- **Permutation**: operations are reordered through their dependency graph into a semantically equivalent sequence.
- **Scrambling**: operations are placed in a randomized physical layout connected by jumps that follow their original execution order.
- **Mutation**: operations are rewritten into logically equivalent forms whose structure varies between builds.
- **Encryption**: immediate values are masked against a rolling key, with each block's key derived from the ciphertext tail of the previous so tampering silently corrupts all that follow.
- **Patching**: virtualized blocks are replaced with dispatch stubs that transfer control to the VM.

### 2. Runtime

#### Bootstrap
- **Assembly**: the runtime is assembled directly into the output binary with code and data shuffled into a randomized layout.
- **Imports**: the imports are resolved at runtime by hashes of module and export names.

#### Execution
- **Dispatch**: a stub transfers CPU state to the VM, which decrypts and interprets bytecode through indirect dispatch.
- **Isolation**: a thread maintains an isolated context in thread-local storage, with a child context for nested execution.
- **Exceptions**: a vectored handler catches faults inside the VM and reconstructs the CPU context for external handlers.

#### Protection
- **Attestation**: anti-debug and integrity checks run as VM bytecode and feed directly into block decryption, silently corrupting execution on tampering or debugging.

## Testing

The `tests` crate spins up an instrumented VM and compares its behavior against the CPU.

- **Instructions**: each instruction is executed through the VM and the resulting register and vector state is compared against native execution.
- **Permutation**: each instruction sequence's dependency graph is exhaustively enumerated, with every valid ordering executed through the VM and verified.

## Usage
`cargo run --release --bin obfuscator -- <filename> --virtualization`

## Contributing
1. Fork it
2. Create your branch (`git checkout -b my-change`)
3. Commit your changes (`git commit -m "changed something"`)
4. Push to the branch (`git push origin my-change`)
5. Create new pull request
