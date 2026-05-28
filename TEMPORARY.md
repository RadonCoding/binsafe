```js
  BEFORE:
    sub [rbp+4],r15d
    add r15d,r13d
    sub r15d,[rbp]
    mov r12w,0FFFFh
    nop dword ptr [rax+rax]
  LIFTED:
    // A:
    // READS: [r15, MEMORY(rbp + 4...rbp + 8)]
    // WRITES: [MEMORY(rbp + 4...rbp + 8)] & FLAGS
    // mov [rbp + 4], [rbp + 4] - r15d 
    LoadAddress(VMMem(Rbp, None, 1, 4, None))
    LoadMemory(Lower32)                       // store [rbp + 4]
    LoadRegister(Lower32, R15)                // store r15d
    Sub(Lower32)                              // store load - load
    LoadAddress(VMMem(Rbp, None, 1, 4, None))
    StoreMemory(Lower32)                      // [rbp + 4] = load

    // B:
    // READS: [r15, r13]
    // WRITES: [r15] & FLAGS
    // mov r15d, r15d - r13d
    LoadRegister(Lower32, R15)                // store r15d
    LoadRegister(Lower32, R13)                // store r13d
    Add(Lower32)                              // store load + load
    StoreRegister(Lower32, R15)               // r15d = load

    // C:
    // READS: [r15, MEMORY(rbp...rbp + 4)]
    // WRITES: [r15] + FLAGS
    // mov r15d, r15d - [rbp]
    LoadRegister(Lower32, R15)                // store r15d
    LoadAddress(VMMem(Rbp, None, 1, 0, None))
    LoadMemory(Lower32)                       // store [rbp] 
    Sub(Lower32)                              // store load - load
    StoreRegister(Lower32, R15)               // r15d = load
    
    // D:
    // WRITES: [r12]
    // mov r12w, 0xFFFF
    LoadImmediate(Lower16, [255, 255])        // store 0xFFFF
    StoreRegister(Lower16, R12)               // r12w = load

    /*
        SIMPLE CONCLUSION(S): 
        D can execute at any point,
        C must execute after B, 
        A must execute before B & C

        ADVANCED CONCLUSION(S): 
        A can execute at any point if it stores the initial value of R15 since [rbp + 4]...[rbp + 8] memory range is not read,
        C does not necessarily have to execute last to keep FLAGS in-sync with original flow in-case it saves FLAGS and loads at the end.
        B must always execute before C due to the R/W dependency on R15,

        An instruction that writes NBranch register must always be executed last.

        Flags and such dont matter because the instruction originally modified flags last can store flags once its done and load at the end.
    **/
  MUTATED:
    
```