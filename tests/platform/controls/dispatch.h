// The dispatch-target walk, in C, so a control reads the table without linking
// the library. `regions.h` does the same job for the Mach region walk.
//
// A loader resolves an imported call through a table of pointers, and each
// entry of that table is a dispatch target. `dl_iterate_phdr` names every
// loaded object and gives its program headers, `PT_DYNAMIC` names the
// relocation table of that object, and each jump-slot relocation names one
// table entry. Reading that entry gives the address the call reaches now.
//
// No path in a comment here holds a star, because a star and a slash close a
// comment.

#ifndef FIDELITY_DISPATCH_H
#define FIDELITY_DISPATCH_H

#define _GNU_SOURCE
#include <elf.h>
#include <link.h>
#include <string.h>

#if defined(__aarch64__)
#define FIDELITY_JUMP_SLOT R_AARCH64_JUMP_SLOT
#elif defined(__x86_64__)
#define FIDELITY_JUMP_SLOT R_X86_64_JUMP_SLOT
#else
#error "this control covers aarch64 and x86_64"
#endif

#define MOST_OBJECTS 256
#define MOST_SLOTS 16384

struct object {
    const char *name;
    ElfW(Addr) base;
    ElfW(Addr) low;
    ElfW(Addr) high;
    int binds_now;
    const ElfW(Rela) * relocations;
    size_t relocation_count;
    const ElfW(Sym) * symbols;
    const char *strings;
    size_t slot_count;
};

struct slot {
    ElfW(Addr) * where;
    ElfW(Addr) value;
    const char *name;
    int object;
};

static struct object objects[MOST_OBJECTS];
static int object_count;
static struct slot slots[MOST_SLOTS];
static int slot_count;

// The loader leaves the dynamic array as the linker wrote it, so an entry of a
// shared object holds an address relative to the base of that object. A vaddr
// sits far below the base that the kernel picks, so a value above the base is
// already absolute. The main image of a build that is not position independent
// has a base of zero, and it takes the same path.
static ElfW(Addr) fidelity_absolute(ElfW(Addr) base, ElfW(Addr) value)
{
    return value >= base ? value : base + value;
}

static int fidelity_collect(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    (void)data;
    if (object_count >= MOST_OBJECTS) {
        return 0;
    }

    struct object *object = &objects[object_count];
    memset(object, 0, sizeof *object);
    object->name = info->dlpi_name && info->dlpi_name[0] ? info->dlpi_name : "the main image";
    object->base = info->dlpi_addr;
    object->low = (ElfW(Addr)) - 1;

    const ElfW(Dyn) *dynamic = NULL;
    for (int index = 0; index < info->dlpi_phnum; index++) {
        const ElfW(Phdr) *header = &info->dlpi_phdr[index];
        if (header->p_type == PT_LOAD) {
            ElfW(Addr) start = info->dlpi_addr + header->p_vaddr;
            if (start < object->low) {
                object->low = start;
            }
            if (start + header->p_memsz > object->high) {
                object->high = start + header->p_memsz;
            }
        }
        if (header->p_type == PT_DYNAMIC) {
            dynamic = (const ElfW(Dyn) *)(info->dlpi_addr + header->p_vaddr);
        }
    }

    if (dynamic) {
        ElfW(Addr) table = 0;
        ElfW(Addr) symbols = 0;
        ElfW(Addr) strings = 0;
        ElfW(Xword) bytes = 0;
        ElfW(Sxword) kind = 0;
        for (const ElfW(Dyn) *entry = dynamic; entry->d_tag != DT_NULL; entry++) {
            switch (entry->d_tag) {
            case DT_JMPREL:
                table = entry->d_un.d_ptr;
                break;
            case DT_PLTRELSZ:
                bytes = entry->d_un.d_val;
                break;
            case DT_PLTREL:
                kind = (ElfW(Sxword))entry->d_un.d_val;
                break;
            case DT_SYMTAB:
                symbols = entry->d_un.d_ptr;
                break;
            case DT_STRTAB:
                strings = entry->d_un.d_ptr;
                break;
            case DT_BIND_NOW:
                object->binds_now = 1;
                break;
            case DT_FLAGS:
                if (entry->d_un.d_val & DF_BIND_NOW) {
                    object->binds_now = 1;
                }
                break;
            case DT_FLAGS_1:
                if (entry->d_un.d_val & DF_1_NOW) {
                    object->binds_now = 1;
                }
                break;
            default:
                break;
            }
        }
        // Only the addend form carries a target that this control can read.
        if (table && bytes && kind == DT_RELA) {
            object->relocations = (const ElfW(Rela) *)fidelity_absolute(info->dlpi_addr, table);
            object->relocation_count = bytes / sizeof(ElfW(Rela));
        }
        if (symbols && strings) {
            object->symbols = (const ElfW(Sym) *)fidelity_absolute(info->dlpi_addr, symbols);
            object->strings = (const char *)fidelity_absolute(info->dlpi_addr, strings);
        }
    }

    object_count++;
    return 0;
}

static int fidelity_owner_of(ElfW(Addr) address)
{
    for (int index = 0; index < object_count; index++) {
        if (address >= objects[index].low && address < objects[index].high) {
            return index;
        }
    }
    return -1;
}

// Fills `objects` and `slots` with what the process holds now.
static void fidelity_read_slots(void)
{
    object_count = 0;
    dl_iterate_phdr(fidelity_collect, NULL);

    slot_count = 0;
    for (int index = 0; index < object_count; index++) {
        struct object *object = &objects[index];
        object->slot_count = 0;
        for (size_t entry = 0; entry < object->relocation_count; entry++) {
            const ElfW(Rela) *relocation = &object->relocations[entry];
            if (ELF64_R_TYPE(relocation->r_info) != FIDELITY_JUMP_SLOT) {
                continue;
            }
            if (slot_count >= MOST_SLOTS) {
                return;
            }
            struct slot *slot = &slots[slot_count];
            slot->where = (ElfW(Addr) *)(object->base + relocation->r_offset);
            slot->value = *slot->where;
            slot->object = index;
            slot->name = "";
            if (object->symbols && object->strings) {
                ElfW(Xword) symbol = ELF64_R_SYM(relocation->r_info);
                slot->name = object->strings + object->symbols[symbol].st_name;
            }
            slot_count++;
            object->slot_count++;
        }
    }
}

#endif
