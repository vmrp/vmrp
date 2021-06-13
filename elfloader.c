#include <string.h>
#include "./header/vmrp.h"
#include "./header/elfload.h"
#include "./header/fileLib.h"

#define R_ARM_NONE 0
#define R_ARM_RELATIVE 23

el_status el_applyrela(el_ctx* ctx, Elf_RelA* rel) {
    uintptr_t* p = (uintptr_t*)(rel->r_offset + ctx->base_load_paddr);
    uint32_t type = ELF_R_TYPE(rel->r_info);
    uint32_t sym = ELF_R_SYM(rel->r_info);

    switch (type) {
        case R_ARM_RELATIVE:
            if (sym) {
                EL_DEBUG("%s", "R_ARM_RELATIVE with symbol ref!\n");
                return EL_BADREL;
            }

            EL_DEBUG("el_applyrela Applying R_ARM_RELATIVE reloc @%p\n", p);
            *p = rel->r_addend + ctx->base_load_vaddr;
            break;

        case R_ARM_NONE:
            EL_DEBUG("%s", "R_ARM_NONE\n");
            // break;
        default:
            EL_DEBUG("Bad relocation %u\n", type);
            return EL_BADREL;
    }

    return EL_OK;
}

el_status el_applyrel(el_ctx* ctx, Elf_Rel* rel) {
    uintptr_t* p = (uintptr_t*)(rel->r_offset + ctx->base_load_paddr);
    uint32_t type = ELF_R_TYPE(rel->r_info);
    uint32_t sym = ELF_R_SYM(rel->r_info);

    switch (type) {
        case R_ARM_RELATIVE:
            if (sym) {
                EL_DEBUG("%s", "R_ARM_RELATIVE with symbol ref!\n");
                return EL_BADREL;
            }

            EL_DEBUG("el_applyrel Applying R_ARM_RELATIVE reloc @%p\n", p);
            *p += ctx->base_load_vaddr;
            break;

        case R_ARM_NONE:
            EL_DEBUG("%s", "R_ARM_NONE\n");
            // break;
        default:
            EL_DEBUG("Bad relocation %u\n", type);
            return EL_BADREL;
    }

    return EL_OK;
}

void* rawElf;
void* elfBuf;

static BOOL fpread(el_ctx* ctx, void* dest, size_t nb, size_t offset) {
    uint8* p = rawElf;
    p += offset;
    memcpy(dest, p, nb);
    return TRUE;
}

static void* alloccb(el_ctx* ctx, Elf_Addr phys, Elf_Addr virt, Elf_Addr size) {
    // return (void*)virt;
    return (void*)phys;
}

int32 elfLoad(const char* filename, uint32_t* outEntryPoint) {
    el_ctx ctx;
    el_status stat;

    rawElf = readFile(filename);
    if (rawElf == NULL) {
        return MR_FAILED;
    }
    ctx.pread = fpread;
    stat = el_init(&ctx);
    if (stat) {
        EL_DEBUG("initialising: error %d\n", stat);
        goto err;
    }

    EL_DEBUG("ctx.align:%d, ctx.memsz:%d\n", ctx.align, ctx.memsz);
    // if (posix_memalign(&elfBuf, ctx.align, ctx.memsz)) {
    //     perror("memalign");
    //     return 1;
    // }

    if (ctx.memsz > CODE_SIZE) {
        printf("ctx.memsz > CODE_SIZE\n");
        goto err;
    }
    elfBuf = getMrpMemPtr(CODE_ADDRESS);
    ctx.base_load_vaddr = CODE_ADDRESS;
    ctx.base_load_paddr = (uintptr_t)elfBuf;
    stat = el_load(&ctx, alloccb);
    if (stat) {
        EL_DEBUG("loading: error %d\n", stat);
        goto err;
    }

    stat = el_relocate(&ctx);
    if (stat) {
        EL_DEBUG("relocating: error %d\n", stat);
        goto err;
    }
    EL_DEBUG("Binary entrypoint is 0x%X\n", ctx.ehdr.e_entry);
    *outEntryPoint = toMrpMemAddr((void*)(ctx.ehdr.e_entry + (uintptr_t)elfBuf));

    free(rawElf);
    rawElf = NULL;
    return MR_SUCCESS;
err:
    free(rawElf);
    rawElf = NULL;
    return MR_FAILED;
}
