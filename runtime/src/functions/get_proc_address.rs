use crate::{
    define_offset,
    runtime::{FnDef, Runtime},
};
use iced_x86::code_asm::{
    eax, ecx, ptr, r12, r13, r14, r15, rax, rbp, rbx, rcx, rdx, rsi, rsp, word_ptr,
};

// void* (const char*, const char*)
pub fn build(rt: &mut Runtime) {
    let mut module_loop = rt.asm.create_label();
    let mut export_loop = rt.asm.create_label();
    let mut name_loop = rt.asm.create_label();
    let mut found = rt.asm.create_label();
    let mut not_found = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    let mut offset = 0;

    define_offset!(number_of_names, offset, 4);
    define_offset!(address_of_names, offset, 8);
    define_offset!(address_of_name_ordinals, offset, 8);
    define_offset!(address_of_functions, offset, 8);

    let stack_size = (offset + 0xF) & !0xF;

    // push rbp
    rt.asm.push(rbp).unwrap();
    // mov rbp, rsp
    rt.asm.mov(rbp, rsp).unwrap();
    // sub rsp, stack_size
    rt.asm.sub(rsp, stack_size).unwrap();

    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();
    // push r15
    rt.asm.push(r15).unwrap();
    // push rbx
    rt.asm.push(rbx).unwrap();
    // push rsi
    rt.asm.push(rsi).unwrap();

    // mov r13, rcx
    rt.asm.mov(r13, rcx).unwrap();
    // mov r14, rdx
    rt.asm.mov(r14, rdx).unwrap();

    // mov rax, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
    rt.asm.mov(rax, ptr(0x60).gs()).unwrap();
    // mov rax, [rax + 0x18] -> PEB_LDR_DATA *PEB->Ldr
    rt.asm.mov(rax, ptr(rax + 0x18)).unwrap();

    // mov rax, [rax + 0x20] -> LDR_DATA_TABLE_ENTRY *PEB->Ldr->InMemoryOrderModuleList.Flink
    rt.asm.mov(rax, ptr(rax + 0x20)).unwrap();
    // mov r13, rax
    rt.asm.mov(r15, rax).unwrap();

    // module_loop:
    rt.asm.set_label(&mut module_loop).unwrap();
    {
        // mov rbx, rax
        rt.asm.mov(rbx, rax).unwrap();

        // lea rcx, [rax + 0x48] -> UNICODE_STRING *LDR_DATA_TABLE_ENTRY->BaseDllName
        rt.asm.lea(rcx, ptr(rax + 0x48)).unwrap();
        // mov rcx, [rcx + 0x8] -> PWSTR *UNICODE_STRING->Buffer
        rt.asm.mov(rcx, ptr(rcx + 0x8)).unwrap();
        // mov rdx, r13
        rt.asm.mov(rdx, r13).unwrap();
        // call compare_unicode_to_ansi
        rt.asm
            .call(rt.func_labels[&FnDef::CompareUnicodeToAnsi])
            .unwrap();

        // test rax, rax
        rt.asm.test(rax, rax).unwrap();
        // jnz ...
        rt.asm.jnz(export_loop).unwrap();

        // mov rax, rbx
        rt.asm.mov(rax, rbx).unwrap();
        // mov rax, [rax] -> LIST_ENTRY *LDR_DATA_TABLE_ENTRY->InMemoryOrderLinks.Flink
        rt.asm.mov(rax, ptr(rax)).unwrap();
        // cmp rax, r15
        rt.asm.cmp(rax, r15).unwrap();
        // je ...
        rt.asm.je(not_found).unwrap();
        // jmp ...
        rt.asm.jmp(module_loop).unwrap();
    }

    rt.asm.set_label(&mut export_loop).unwrap();
    {
        // mov rax, rbx
        rt.asm.mov(rax, rbx).unwrap();
        // mov rax, [rax + 0x20] -> PVOID LDR_DATA_TABLE_ENTRY->DllBase
        rt.asm.mov(rax, ptr(rax + 0x20)).unwrap();
        // mov r12, rax
        rt.asm.mov(r12, rax).unwrap();

        // mov ecx, [rax + 0x3C] -> IMAGE_DOS_HEADER->e_lfanew
        rt.asm.mov(ecx, ptr(rax + 0x3C)).unwrap();
        // add rax, rcx -> IMAGE_NT_HEADERS
        rt.asm.add(rax, rcx).unwrap();
        // add rax, 0x18 -> IMAGE_OPTIONAL_HEADER
        rt.asm.add(rax, 0x18).unwrap();
        // add rax, 0x60 -> IMAGE_DATA_DIRECTORY IMAGE_OPTIONAL_HEADER->DataDirectory[0]
        rt.asm.add(rax, 0x70).unwrap();
        // mov ecx, [rax] -> DWORD IMAGE_DATA_DIRECTORY->VirtualAddress
        rt.asm.mov(ecx, ptr(rax)).unwrap();
        // add rcx, r12 -> IMAGE_EXPORT_DIRECTORY
        rt.asm.add(rcx, r12).unwrap();

        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();

        // mov ecx, [rax + 0x18] -> DWORD IMAGE_EXPORT_DIRECTORY->NumberOfNames
        rt.asm.mov(ecx, ptr(rax + 0x18)).unwrap();
        // mov [rbp - ...], ecx
        rt.asm.mov(ptr(rbp - number_of_names), ecx).unwrap();

        // mov ecx, [rax + 0x20] -> DWORD IMAGE_EXPORT_DIRECTORY->AddressOfNames
        rt.asm.mov(ecx, ptr(rax + 0x20)).unwrap();
        // add rcx, r12 -> IMAGE_EXPORT_DIRECTORY
        rt.asm.add(rcx, r12).unwrap();
        // mov [rbp - ...], ecx
        rt.asm.mov(ptr(rbp - address_of_names), rcx).unwrap();

        // mov ecx, [rax + 0x24] -> DWORD IMAGE_EXPORT_DIRECTORY->AddressOfNameOrdinals
        rt.asm.mov(ecx, ptr(rax + 0x24)).unwrap();
        // add rcx, r12
        rt.asm.add(rcx, r12).unwrap();
        // mov [rbp - ...], rcx
        rt.asm
            .mov(ptr(rbp - address_of_name_ordinals), rcx)
            .unwrap();

        // mov ecx, [rax + 0x1C] -> DWORD IMAGE_EXPORT_DIRECTORY->AddressOfFunctions RVA
        rt.asm.mov(ecx, ptr(rax + 0x1C)).unwrap();
        // add rcx, r12 -> PDWORD AddressOfFunctions VA
        rt.asm.add(rcx, r12).unwrap();
        // mov [rbp - ...], rcx
        rt.asm.mov(ptr(rbp - address_of_functions), rcx).unwrap();
    }

    // xor rsi, rsi
    rt.asm.xor(rsi, rsi).unwrap();

    rt.asm.set_label(&mut name_loop).unwrap();
    {
        // cmp ecx, [rbp - ...]
        rt.asm.cmp(ecx, ptr(rbp - number_of_names)).unwrap();
        // je not_found
        rt.asm.jge(not_found).unwrap();

        // mov rax, [rbp - ...]
        rt.asm.mov(rax, ptr(rbp - address_of_names)).unwrap();
        // mov eax, [rax + rsi*4]
        rt.asm.mov(eax, ptr(rax + rsi * 4)).unwrap();
        // add rax, r12
        rt.asm.add(rax, r12).unwrap();

        // mov rcx, rax
        rt.asm.mov(rcx, rax).unwrap();
        // mov rax, r14
        rt.asm.mov(rdx, r14).unwrap();
        // call ...
        rt.asm.call(rt.func_labels[&FnDef::CompareAnsi]).unwrap();

        rt.asm.test(rax, rax).unwrap();
        rt.asm.jnz(found).unwrap();

        rt.asm.inc(rsi).unwrap();
        rt.asm.jmp(name_loop).unwrap();
    }

    rt.asm.set_label(&mut found).unwrap();
    {
        // mov rax, [rbp - ...]
        rt.asm
            .mov(rax, ptr(rbp - address_of_name_ordinals))
            .unwrap();
        // movzx rdx, word ptr [rax + rsi*2]
        rt.asm.movzx(rdx, word_ptr(rax + rsi * 2)).unwrap();

        // mov rax, [rbp - ...]
        rt.asm.mov(rax, ptr(rbp - address_of_functions)).unwrap();
        // mov eax, [rax + rdx*4]
        rt.asm.mov(eax, ptr(rax + rdx * 4)).unwrap();
        // add rax, r12
        rt.asm.add(rax, r12).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut not_found).unwrap();
    {
        // xor rax, rax
        rt.asm.xor(rax, rax).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // pop rsi
        rt.asm.pop(rsi).unwrap();
        // pop rbx
        rt.asm.pop(rbx).unwrap();
        // pop r15
        rt.asm.pop(r15).unwrap();
        // pop r14
        rt.asm.pop(r14).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // pop r12
        rt.asm.pop(r12).unwrap();

        // mov rsp, rbp
        rt.asm.mov(rsp, rbp).unwrap();
        // pop rbp
        rt.asm.pop(rbp).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
