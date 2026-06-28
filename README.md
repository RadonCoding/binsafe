![](example.gif)

Code virtualizer for compiled 64-bit portable executables.

## How it works

### 1. Obfuscator

#### Mutation
- **Substitution**: instructions are substituted with algebraically equivalent sequences using dead-flag analysis to preserve correctness.

#### Virtualization
- **Lifting**: instructions are translated into a stack-machine bytecode the runtime interprets.
- **Permutation**: operations are reordered through their logical dependencies into a semantically equivalent sequence.
- **Scrambling**: operations are placed in a randomized physical layout connected by inserted jumps that follow their original execution order.
- **Mutation**: operations are rewritten into logically equivalent forms whose structure varies between builds.
- **Encryption**: immediate values are masked against a rolling key that advances between every immediate.
- **Chaining**: each block's decryption key is derived from the ciphertext tail of the previous block, so tampering with any block silently corrupts every block that follows.
- **Patching**: virtualized blocks are replaced with dispatch stubs that transfer control to the VM.

### 2. Runtime

#### State
- **Thread Contexts**: each thread maintains an isolated context in [Thread Local Storage](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-local-storage).
- **Shadow Contexts**: each context maintains a separate child context for nested execution.

#### Execution
- **Dispatch**: a stub transfers CPU state to the VM, which interprets bytecode through indirect dispatch to handler functions.
- **Exceptions**: a vectored exception handler catches faults inside the VM region and reconstructs the CPU context for external handlers.

#### Protection
- **Attestation**: anti-debug and integrity checks execute as VM bytecode and directly influence block decryption, corrupting execution silently on tampering or debugging rather than producing detectable failures.

## Testing

The `tests` crate spins up a minimal version of the VM instrumented for testing.

- **Instructions**: each instruction is executed through the VM and the resulting context is compared against the CPU.
- **Permutation**: each instruction sequence's dependency graph is exhaustively executed through the VM and verified.

## Usage

`cargo run --release --bin obfuscator -- <filename> --virtualization --mutation`

## Contributing
1. Fork it
2. Create your branch (`git checkout -b my-change`)
3. Commit your changes (`git commit -m "changed something"`)
4. Push to the branch (`git push origin my-change`)
5. Create new pull request