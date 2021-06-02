/* Copyright © 2014, Owen Shepherd
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef ELFLOAD_H
#define ELFLOAD_H

#include "elf.h"

// typedef uint32 size_t;
// typedef int32 BOOL;
// typedef uint32 uintptr_t;
// typedef uint32 uint32_t;

void logPrint(char *msg);

#if 0
#define EL_DEBUG(fmt, ...)                        \
    do {                                          \
        char ubfffffff[256];                      \
        mrc_sprintf(ubfffffff, fmt, __VA_ARGS__); \
        logPrint(ubfffffff);                      \
    } while (0)
#else
// #define EL_DEBUG(fmt, ...) LOG(fmt, __VA_ARGS__)
#define EL_DEBUG(fmt, ...)
#endif

typedef enum {
    EL_OK = 0,

    EL_EIO,
    EL_ENOMEM,

    EL_NOTELF,
    EL_WRONGBITS,
    EL_WRONGENDIAN,
    EL_WRONGARCH,
    EL_WRONGOS,
    EL_NOTEXEC,
    EL_NODYN,
    EL_BADREL

} el_status;

typedef struct el_ctx {
    BOOL(*pread)
    (struct el_ctx *ctx, void *dest, size_t nb, size_t offset);

    /* base_load_* -> address we are actually going to load at
     */
    Elf_Addr
        base_load_paddr,
        base_load_vaddr;

    /* size in memory of binary */
    Elf_Addr memsz;

    /* required alignment */
    Elf_Addr align;

    /* ELF header */
    Elf_Ehdr ehdr;

    /* Offset of dynamic table (0 if not ET_DYN) */
    Elf_Off dynoff;
    /* Size of dynamic table (0 if not ET_DYN) */
    Elf_Addr dynsize;
} el_ctx;

el_status el_pread(el_ctx *ctx, void *def, size_t nb, size_t offset);

el_status el_init(el_ctx *ctx);

typedef void *(*el_alloc_cb)(el_ctx *ctx, Elf_Addr phys, Elf_Addr virt, Elf_Addr size);

el_status el_load(el_ctx *ctx, el_alloc_cb alloccb);

/* find the next phdr of type \p type, starting at \p *i.
 * On success, returns EL_OK with *i set to the phdr number, and the phdr loaded
 * in *phdr.
 *
 * If the end of the phdrs table was reached, *i is set to -1 and the contents
 * of *phdr are undefined
 */
el_status el_findphdr(el_ctx *ctx, Elf_Phdr *phdr, uint32 type, unsigned *i);

/* Relocate the loaded executable */
el_status el_relocate(el_ctx *ctx);

/* find a dynamic table entry
 * returns the entry on success, dyn->d_tag = DT_NULL on failure
 */
el_status el_finddyn(el_ctx *ctx, Elf_Dyn *dyn, uint32 type);

typedef struct {
    Elf_Off tableoff;
    Elf_Addr tablesize;
    Elf_Addr entrysize;
} el_relocinfo;

/* find all information regarding relocations of a specific type.
 *
 * pass DT_REL or DT_RELA for type
 * sets ri->entrysize = 0 if not found
 */
el_status el_findrelocs(el_ctx *ctx, el_relocinfo *ri, uint32 type);

int32 elfLoad(const char *filename, uint32_t *outEntryPoint);

#endif
