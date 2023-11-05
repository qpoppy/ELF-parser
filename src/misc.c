#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include "elf_utils.h"

#define ELF_MAGIC "\x7f\x45\x4c\x46"

size_t get_elf_size(char *file_name) {
    struct stat st;
    if (stat(file_name, &st) != 0) {
        fprintf(stderr, "Error: Unable to get file size\n");
        exit(EXIT_FAILURE);
    }
    return st.st_size;
}

bool validate_elf(elf_parser_t *parser) {
    if (memcmp(parser->ehdr.e_ident, ELF_MAGIC, 4) != 0) {
        return false;
    }
    return true;
}

char *dump_elf_flag(int flags) {
    static char buf[256];
    buf[0] = '\0';
    if (flags & ELF_HEADER_FLAG_EXECUTABLE) {
        strcat(buf, "EXECUTABLE ");
    }
    if (flags & ELF_HEADER_FLAG_SHARED) {
        strcat(buf, "SHARED ");
    }
    if (flags & ELF_HEADER_FLAG_RELOCATABLE) {
        strcat(buf, "RELOCATABLE ");
    }
    if (flags & ELF_HEADER_FLAG_CORE) {
        strcat(buf, "CORE ");
    }
    return buf;
}

char *dump_program_type(int type) {
    switch (type) {
        case PT_NULL:
            return "NULL";
        case PT_LOAD:
            return "LOAD";
        case PT_DYNAMIC:
            return "DYNAMIC";
        case PT_INTERP:
            return "INTERP";
        case PT_NOTE:
            return "NOTE";
        case PT_SHLIB:
            return "SHLIB";
        case PT_PHDR:
            return "PHDR";
        case PT_TLS:
            return "TLS";
        case PT_GNU_EH_FRAME:
            return "GNU_EH_FRAME";
        case PT_GNU_STACK:
            return "GNU_STACK";
        case PT_GNU_RELRO:
            return "GNU_RELRO";
        default:
            return "UNKNOWN";
    }
}

char *dump_program_flag(int flag) {
    static char buf[256];
    buf[0] = '\0';
    if (flag & PF_X) {
        strcat(buf, "EXECUTE ");
    }
    if (flag & PF_W) {
        strcat(buf, "WRITE ");
    }
    if (flag & PF_R) {
        strcat(buf, "READ ");
    }
    return buf;
}

char *dump_section_type(int type) {
    switch (type) {
        case SHT_NULL:
            return "NULL";
        case SHT_PROGBITS:
            return "PROGBITS";
        case SHT_SYMTAB:
            return "SYMTAB";
        case SHT_STRTAB:
            return "STRTAB";
        case SHT_RELA:
            return "RELA";
        case SHT_HASH:
            return "HASH";
        case SHT_DYNAMIC:
            return "DYNAMIC";
        case SHT_NOTE:
            return "NOTE";
        case SHT_NOBITS:
            return "NOBITS";
        case SHT_REL:
            return "REL";
        case SHT_SHLIB:
            return "SHLIB";
        case SHT_DYNSYM:
            return "DYNSYM";
        default:
            return "UNKNOWN";
    }
}

char *dump_section_flag(unsigned long flag) {
    static char buf[256];
    buf[0] = '\0';
    if (flag & SHF_WRITE) {
        strcat(buf, "WRITE ");
    }
    if (flag & SHF_ALLOC) {
        strcat(buf, "ALLOC ");
    }
    if (flag & SHF_EXECINSTR) {
        strcat(buf, "EXECUTE ");
    }
    return buf;
}

char *dump_symbol_type(unsigned char type) {
    switch (type) {
        case STT_NOTYPE:
            return "NOTYPE";
        case STT_OBJECT:
            return "OBJECT";
        case STT_FUNC:
            return "FUNC";
        case STT_SECTION:
            return "SECTION";
        case STT_FILE:
            return "FILE";
        default:
            return "UNKNOWN";
    }
}

char *dump_symbol_bind(unsigned char binding) {
    switch (binding) {
        case STB_LOCAL:
            return "LOCAL";
        case STB_GLOBAL:
            return "GLOBAL";
        case STB_WEAK:
            return "WEAK";
        default:
            return "UNKNOWN";
    }
}

char *dump_symbol_visibility(unsigned char vision) {
    switch (vision) {
        case STV_DEFAULT:
            return "DEFAULT";
        case STV_INTERNAL:
            return "INTERNAL";
        case STV_HIDDEN:
            return "HIDDEN";
        case STV_PROTECTED:
            return "PROTECTED";
        default:
            return "UNKNOWN";
    }
}
