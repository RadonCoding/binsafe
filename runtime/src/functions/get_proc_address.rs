use crate::{
    define_offset,
    runtime::{FnDef, Runtime},
};
use iced_x86::code_asm::{
    eax, ecx, ptr, r12, r13, r14, r15, r15d, rax, rbp, rbx, rcx, rdx, rsp, word_ptr,
};

// void* (const char*, const char*)
pub fn build(rt: &mut Runtime) {
    let mut module_loop = rt.asm.create_label();
    let mut get_exports = rt.asm.create_label();
    let mut export_loop = rt.asm.create_label();
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
    // sub rsp, ...
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

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // mov rbx, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
    rt.asm.mov(rbx, ptr(0x60).gs()).unwrap();
    // mov rbx, [rbx + 0x18] -> PEB_LDR_DATA *PEB->Ldr
    rt.asm.mov(rbx, ptr(rbx + 0x18)).unwrap();

    // mov rbx, [rbx + 0x20] -> LDR_DATA_TABLE_ENTRY *PEB->Ldr->InMemoryOrderModuleList.Flink
    rt.asm.mov(rbx, ptr(rbx + 0x20)).unwrap();
    // mov r14, rbx
    rt.asm.mov(r14, rbx).unwrap();

    // module_loop:
    rt.asm.set_label(&mut module_loop).unwrap();
    {
        // lea rcx, [rbx + 0x48] -> UNICODE_STRING *LDR_DATA_TABLE_ENTRY->BaseDllName
        rt.asm.lea(rcx, ptr(rbx + 0x48)).unwrap();
        // mov rcx, [rcx + 0x8] -> PWSTR *UNICODE_STRING->Buffer
        rt.asm.mov(rcx, ptr(rcx + 0x8)).unwrap();
        // mov rdx, r12
        rt.asm.mov(rdx, r12).unwrap();
        // call ...
        rt.asm
            .call(rt.func_labels[&FnDef::CompareUnicodeToAnsi])
            .unwrap();

        // test rax, rax
        rt.asm.test(rax, rax).unwrap();
        // jnz ...
        rt.asm.jnz(get_exports).unwrap();

        // mov rbx, [rbx] -> LIST_ENTRY *LDR_DATA_TABLE_ENTRY->InMemoryOrderLinks.Flink
        rt.asm.mov(rbx, ptr(rbx)).unwrap();
        // cmp rbx, r14
        rt.asm.cmp(rbx, r14).unwrap();
        // je ...
        rt.asm.je(not_found).unwrap();

        // jmp ...
        rt.asm.jmp(module_loop).unwrap();
    }

    rt.asm.set_label(&mut get_exports).unwrap();
    {
        // mov rax, [rbx + 0x20] -> VOID *LDR_DATA_TABLE_ENTRY->DllBase
        rt.asm.mov(rax, ptr(rbx + 0x20)).unwrap();
        // mov rbx, rax
        rt.asm.mov(rbx, rax).unwrap();

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
        // add rcx, rbx -> IMAGE_EXPORT_DIRECTORY
        rt.asm.add(rcx, rbx).unwrap();

        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();

        // mov ecx, [rax + 0x18] -> DWORD IMAGE_EXPORT_DIRECTORY->NumberOfNames
        rt.asm.mov(ecx, ptr(rax + 0x18)).unwrap();
        // mov [rbp - ...], ecx
        rt.asm.mov(ptr(rbp - number_of_names), ecx).unwrap();

        // mov ecx, [rax + 0x20] -> DWORD IMAGE_EXPORT_DIRECTORY->AddressOfNames
        rt.asm.mov(ecx, ptr(rax + 0x20)).unwrap();
        // add rcx, rbx -> IMAGE_EXPORT_DIRECTORY
        rt.asm.add(rcx, rbx).unwrap();
        // mov [rbp - ...], ecx
        rt.asm.mov(ptr(rbp - address_of_names), rcx).unwrap();

        // mov ecx, [rax + 0x24] -> DWORD IMAGE_EXPORT_DIRECTORY->AddressOfNameOrdinals
        rt.asm.mov(ecx, ptr(rax + 0x24)).unwrap();
        // add rcx, rbx
        rt.asm.add(rcx, rbx).unwrap();
        // mov [rbp - ...], rcx
        rt.asm
            .mov(ptr(rbp - address_of_name_ordinals), rcx)
            .unwrap();

        // mov ecx, [rax + 0x1C] -> DWORD IMAGE_EXPORT_DIRECTORY->AddressOfFunctions
        rt.asm.mov(ecx, ptr(rax + 0x1C)).unwrap();
        // add rcx, rbx -> PDWORD AddressOfFunctions VA
        rt.asm.add(rcx, rbx).unwrap();
        // mov [rbp - ...], rcx
        rt.asm.mov(ptr(rbp - address_of_functions), rcx).unwrap();

        // xor r15, r15
        rt.asm.xor(r15, r15).unwrap();

        rt.asm.set_label(&mut export_loop).unwrap();
        {
            // cmp r15d, [rbp - ...]
            rt.asm.cmp(r15d, ptr(rbp - number_of_names)).unwrap();
            // je not_found
            rt.asm.je(not_found).unwrap();

            // mov rax, [rbp - ...]
            rt.asm.mov(rax, ptr(rbp - address_of_names)).unwrap();
            // mov eax, [rax + r15*4]
            rt.asm.mov(eax, ptr(rax + r15 * 4)).unwrap();
            // add rax, rbx
            rt.asm.add(rax, rbx).unwrap();

            // mov rcx, rax
            rt.asm.mov(rcx, rax).unwrap();
            // mov rax, r13
            rt.asm.mov(rdx, r13).unwrap();
            // call ...
            rt.asm.call(rt.func_labels[&FnDef::CompareAnsi]).unwrap();

            rt.asm.test(rax, rax).unwrap();
            rt.asm.jnz(found).unwrap();

            rt.asm.inc(r15).unwrap();
            rt.asm.jmp(export_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut found).unwrap();
    {
        // mov rax, [rbp - ...]
        rt.asm
            .mov(rax, ptr(rbp - address_of_name_ordinals))
            .unwrap();
        // movzx rdx, word ptr [rax + r15*2]
        rt.asm.movzx(rdx, word_ptr(rax + r15 * 2)).unwrap();

        // mov rax, [rbp - ...]
        rt.asm.mov(rax, ptr(rbp - address_of_functions)).unwrap();
        // mov eax, [rax + rdx*4]
        rt.asm.mov(eax, ptr(rax + rdx * 4)).unwrap();
        // add rax, rbx
        rt.asm.add(rax, rbx).unwrap();

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
