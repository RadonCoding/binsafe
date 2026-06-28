![](example.gif)

Code virtualizer for compiled 64-bit portable executables.

## How it works

### 1. Obfuscation
- **Mutation**: instructions are substituted with algebraically equivalent sequences using dead-flag analysis to preserve correctness.
- **Virtualization**: instructions are lifted into bytecode and handed off to a runtime VM, replacing the original code with dispatch stubs.

### 2. Virtualization
- **Permutation**: operations are reordered through their dependency graph into a semantically equivalent sequence.
- **Scrambling**: operations are placed in a randomized physical layout connected by jumps that follow their original execution order.
- **Mutation**: operations are rewritten into logically equivalent forms whose structure varies between builds.
- **Encryption**: immediate values are masked against a rolling key, with each block's key derived from the ciphertext tail of the previous block so tampering silently corrupts all that follow.

### 3. Runtime
- **Execution**: a stub transfers CPU state to the VM, which interprets bytecode through indirect dispatch.
- **Isolation**: each thread maintains an isolated context, with a separate child context for nested execution.
- **Exceptions**: a vectored handler catches faults inside the VM and reconstructs the CPU context for external handlers.
- **Attestation**: anti-debug and integrity checks run as VM bytecode and feed directly into block decryption, silently corrupting execution on tampering or debugging.

## Usage
`cargo run --release --bin obfuscator -- <filename> --virtualization --mutation`

## Contributing
1. Fork it
2. Create your branch (`git checkout -b my-change`)
3. Commit your changes (`git commit -m "changed something"`)
4. Push to the branch (`git push origin my-change`)
5. Create new pull request