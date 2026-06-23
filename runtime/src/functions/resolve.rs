use crate::{
    mapper::Mappable,
    runtime::{DataDef, FnDef, ImportDef, Runtime},
    stack,
};
use iced_x86::code_asm::{
    eax, ecx, edx, ptr, r12, r13, r14, r15, r15d, rax, rbp, rbx, rcx, rdx, rsp, word_ptr,
};

// void* (unsigned long)
pub fn build(rt: &mut Runtime) {
    let mut resolve_module = rt.asm.create_label();
    let mut resolve_module_loop = rt.asm.create_label();

    let mut resolve_export = rt.asm.create_label();
    let mut resolve_export_loop = rt.asm.create_label();

    let mut resolve_export_success = rt.asm.create_label();
    let mut resolve_export_failure = rt.asm.create_label();

    let mut epilogue = rt.asm.create_label();

    let mut offset = 0;

    stack!(slot, offset, 8);

    stack!(export_directory, offset, 8);
    stack!(export_directory_rva, offset, 4);
    stack!(export_directory_size, offset, 4);

    stack!(number_of_names, offset, 4);
    stack!(address_of_names, offset, 8);
    stack!(address_of_name_ordinals, offset, 8);
    stack!(address_of_functions, offset, 8);

    let stack_size = (offset + 0xF) & !0xF;

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

    // push rbp
    rt.asm.push(rbp).unwrap();
    // mov rbp, rsp
    rt.asm.mov(rbp, rsp).unwrap();
    // sub rsp, ...
    rt.asm.sub(rsp, stack_size).unwrap();

    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::ImportAddresses]))
        .unwrap();
    // lea rax, [rax + rcx*8]
    rt.asm.lea(rax, ptr(rax + rcx * 8)).unwrap();
    // mov [rsp + ...], rax
    rt.asm.mov(ptr(rsp + slot), rax).unwrap();

    // mov rax, [rax]
    rt.asm.mov(rax, ptr(rax)).unwrap();
    // test rax, rax
    rt.asm.test(rax, rax).unwrap();
    // jnz ...
    rt.asm.jnz(epilogue).unwrap();

    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::ImportNames]))
        .unwrap();
    // mov rdx, [rax]
    rt.asm.mov(rdx, ptr(rax)).unwrap();
    // test rdx, rdx
    rt.asm.test(rdx, rdx).unwrap();
    // jnz ...
    rt.asm.jnz(resolve_module).unwrap();

    for def in ImportDef::VARIANTS {
        let (module_def, export_def) = def.get();

        let slot = rt.mapper.index(*def) as i32 * 16;

        // lea rdx, [...]
        rt.asm.mov(rdx, ptr(rt.hash_labels[&module_def])).unwrap();
        // mov [rax + ...], rdx
        rt.asm.mov(ptr(rax + slot), rdx).unwrap();
        // mov rdx, [...]
        rt.asm.mov(rdx, ptr(rt.hash_labels[&export_def])).unwrap();
        // mov [rax + ...], rdx
        rt.asm.mov(ptr(rax + slot + 0x8), rdx).unwrap();
    }

    rt.asm.set_label(&mut resolve_module).unwrap();
    {
        // shl rcx, 0x4
        rt.asm.shl(rcx, 0x4).unwrap();
        // mov r12, [rax + rcx]
        rt.asm.mov(r12, ptr(rax + rcx)).unwrap();
        // mov r13, [rax + rcx + 0x8]
        rt.asm.mov(r13, ptr(rax + rcx + 0x8)).unwrap();

        // mov rbx, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
        rt.asm.mov(rbx, ptr(0x60).gs()).unwrap();
        // mov rbx, [rbx + 0x18] -> PEB_LDR_DATA *PEB->Ldr
        rt.asm.mov(rbx, ptr(rbx + 0x18)).unwrap();

        // mov rbx, [rbx + 0x20] -> LDR_DATA_TABLE_ENTRY *PEB->Ldr->InMemoryOrderModuleList.Flink
        rt.asm.mov(rbx, ptr(rbx + 0x20)).unwrap();
        // mov r14, rbx
        rt.asm.mov(r14, rbx).unwrap();

        rt.asm.set_label(&mut resolve_module_loop).unwrap();
        {
            // lea rcx, [rbx + 0x48] -> UNICODE_STRING *LDR_DATA_TABLE_ENTRY->BaseDllName
            rt.asm.lea(rcx, ptr(rbx + 0x48)).unwrap();
            // mov rcx, [rcx + 0x8] -> PWSTR *UNICODE_STRING->Buffer
            rt.asm.mov(rcx, ptr(rcx + 0x8)).unwrap();
            // mov rdx, 0x1
            rt.asm.mov(rdx, 0x1u64).unwrap();
            // call ...
            rt.asm.call(rt.function_labels[&FnDef::Hash]).unwrap();

            // cmp rax, r12
            rt.asm.cmp(rax, r12).unwrap();
            // je ...
            rt.asm.je(resolve_export).unwrap();

            // mov rbx, [rbx] -> LIST_ENTRY *LDR_DATA_TABLE_ENTRY->InMemoryOrderLinks.Flink
            rt.asm.mov(rbx, ptr(rbx)).unwrap();
            // cmp rbx, r14
            rt.asm.cmp(rbx, r14).unwrap();
            // je ...
            rt.asm.je(resolve_export_failure).unwrap();

            // jmp ...
            rt.asm.jmp(resolve_module_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut resolve_export).unwrap();
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
        // mov [rsp + ...], ecx
        rt.asm.mov(ptr(rsp + export_directory_rva), ecx).unwrap();

        // mov ecx, [rax + 0x4] -> DWORD IMAGE_DATA_DIRECTORY->Size
        rt.asm.mov(ecx, ptr(rax + 0x4)).unwrap();
        // mov [rsp + ...], ecx
        rt.asm.mov(ptr(rsp + export_directory_size), ecx).unwrap();

        // mov ecx, [rsp + ...]
        rt.asm.mov(ecx, ptr(rsp + export_directory_rva)).unwrap();
        // add rcx, rbx -> IMAGE_EXPORT_DIRECTORY
        rt.asm.add(rcx, rbx).unwrap();
        // mov [rsp + ...], rcx
        rt.asm.mov(ptr(rsp + export_directory), rcx).unwrap();

        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();

        // mov ecx, [rax + 0x18] -> DWORD IMAGE_EXPORT_DIRECTORY->NumberOfNames
        rt.asm.mov(ecx, ptr(rax + 0x18)).unwrap();
        // mov [rsp + ...], ecx
        rt.asm.mov(ptr(rsp + number_of_names), ecx).unwrap();

        // mov ecx, [rax + 0x20] -> DWORD IMAGE_EXPORT_DIRECTORY->AddressOfNames
        rt.asm.mov(ecx, ptr(rax + 0x20)).unwrap();
        // add rcx, rbx -> IMAGE_EXPORT_DIRECTORY
        rt.asm.add(rcx, rbx).unwrap();
        // mov [rsp + ...], ecx
        rt.asm.mov(ptr(rsp + address_of_names), rcx).unwrap();

        // mov ecx, [rax + 0x24] -> DWORD IMAGE_EXPORT_DIRECTORY->AddressOfNameOrdinals
        rt.asm.mov(ecx, ptr(rax + 0x24)).unwrap();
        // add rcx, rbx
        rt.asm.add(rcx, rbx).unwrap();
        // mov [rsp + ...], rcx
        rt.asm
            .mov(ptr(rsp + address_of_name_ordinals), rcx)
            .unwrap();

        // mov ecx, [rax + 0x1C] -> DWORD IMAGE_EXPORT_DIRECTORY->AddressOfFunctions
        rt.asm.mov(ecx, ptr(rax + 0x1C)).unwrap();
        // add rcx, rbx -> PDWORD AddressOfFunctions VA
        rt.asm.add(rcx, rbx).unwrap();
        // mov [rsp + ...], rcx
        rt.asm.mov(ptr(rsp + address_of_functions), rcx).unwrap();

        // xor r15, r15
        rt.asm.xor(r15, r15).unwrap();

        rt.asm.set_label(&mut resolve_export_loop).unwrap();
        {
            // cmp r15d, [rsp + ...]
            rt.asm.cmp(r15d, ptr(rsp + number_of_names)).unwrap();
            // je not_found
            rt.asm.je(resolve_export_failure).unwrap();

            // mov rax, [rsp + ...]
            rt.asm.mov(rax, ptr(rsp + address_of_names)).unwrap();
            // mov eax, [rax + r15*4]
            rt.asm.mov(eax, ptr(rax + r15 * 4)).unwrap();
            // add rax, rbx
            rt.asm.add(rax, rbx).unwrap();

            // mov rcx, rax
            rt.asm.mov(rcx, rax).unwrap();
            // xor rdx, rdx
            rt.asm.xor(rdx, rdx).unwrap();
            // call ...
            rt.asm.call(rt.function_labels[&FnDef::Hash]).unwrap();

            // cmp rax, r13
            rt.asm.cmp(rax, r13).unwrap();
            // je ...
            rt.asm.je(resolve_export_success).unwrap();

            // inc r15
            rt.asm.inc(r15).unwrap();
            // jmp ...
            rt.asm.jmp(resolve_export_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut resolve_export_success).unwrap();
    {
        // mov rax, [rsp + ...]
        rt.asm
            .mov(rax, ptr(rsp + address_of_name_ordinals))
            .unwrap();
        // movzx rcx, [rax + r15*2]
        rt.asm.movzx(rcx, word_ptr(rax + r15 * 2)).unwrap();

        // mov rax, [rsp + ...]
        rt.asm.mov(rax, ptr(rsp + address_of_functions)).unwrap();
        // mov eax, [rax + rcx*4]
        rt.asm.mov(eax, ptr(rax + rcx * 4)).unwrap();
        // add rax, rbx
        rt.asm.add(rax, rbx).unwrap();

        // mov rcx, [rax - rbx]
        rt.asm.mov(rcx, rax).unwrap();
        // sub rcx, rbx
        rt.asm.sub(rcx, rbx).unwrap();

        // mov edx, [...]
        rt.asm.mov(edx, ptr(rsp + export_directory_rva)).unwrap();

        // cmp ecx, edx
        rt.asm.cmp(ecx, edx).unwrap();
        // jb ...
        rt.asm.jb(epilogue).unwrap();

        // add edx, [rsp + ...]
        rt.asm.add(edx, ptr(rsp + export_directory_size)).unwrap();

        // cmp edx, edx
        rt.asm.cmp(edx, edx).unwrap();
        // jae ...
        rt.asm.jae(epilogue).unwrap();

        // TODO: Resolve forwarder strings
    }

    rt.asm.set_label(&mut resolve_export_failure).unwrap();
    {
        // xor rax, rax
        rt.asm.xor(rax, rax).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rcx, [rsp + ...]
        rt.asm.mov(rcx, ptr(rsp + slot)).unwrap();
        // mov [rcx], rax
        rt.asm.mov(ptr(rcx), rax).unwrap();

        // mov rsp, rbp
        rt.asm.mov(rsp, rbp).unwrap();
        // pop rbp
        rt.asm.pop(rbp).unwrap();

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

        // ret
        rt.asm.ret().unwrap();
    }
}
