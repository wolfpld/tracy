#ifndef __TRACYELF_HPP__
#define __TRACYELF_HPP__

#include <stdint.h>

#if !defined(__GLIBC__) && !defined(__WORDSIZE)
// include __WORDSIZE headers for musl
#  include <bits/reg.h>
#endif

namespace tracy
{

using elf_half = uint16_t;
using elf_word = uint32_t;
using elf_sword = int32_t;

#if __WORDSIZE == 32
    using elf_addr = uint32_t;
    using elf_off = uint32_t;
    using elf_xword = uint32_t;
#else
    using elf_addr = uint64_t;
    using elf_off = uint64_t;
    using elf_xword = uint64_t;
#endif

struct elf_ehdr
{
    unsigned char e_ident[16];
    elf_half e_type;
    elf_half e_machine;
    elf_word e_version;
    elf_addr e_entry;
    elf_off e_phoff;
    elf_off e_shoff;
    elf_word e_flags;
    elf_half e_ehsize;
    elf_half e_phentsize;
    elf_half e_phnum;
    elf_half e_shentsize;
    elf_half e_shnum;
    elf_half e_shstrndx;
};

struct elf_phdr
{
    elf_word p_type;
    elf_word p_flags;
    elf_off p_offset;
    elf_addr p_vaddr;
    elf_addr p_paddr;
    elf_xword p_filesz;
    elf_xword p_memsz;
    uint64_t p_align;   // include 32-bit-only flags field for 32-bit compatibility
};

}

#endif
