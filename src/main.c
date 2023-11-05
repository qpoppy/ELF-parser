#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>

typedef struct {
    int fd;
    char *file_name;
    void *map_start;
    Elf64_Ehdr *elf_header;
    Elf64_Phdr *program_header;
    Elf64_Shdr *section_header;
    Elf64_Sym *symbol_table;
} elf_parser_t;

void init_parser(int fd, char *file_name, elf_parser_t *parser) {
    parser->fd = fd;
    parser->file_name = file_name;

    // Determine the size of the ELF binary file
    off_t file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    // Map the file into memory using mmap
    parser->map_start = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (parser->map_start == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    // Set various pointers within the structure to access the ELF header, program header, section header, and symbol table
    parser->elf_header = (Elf64_Ehdr *) parser->map_start;
    parser->program_header = (Elf64_Phdr *) (parser->map_start + parser->elf_header->e_phoff);
    parser->section_header = (Elf64_Shdr *) (parser->map_start + parser->elf_header->e_shoff);
    parser->symbol_table = NULL;
}

void dump_elf_header(elf_parser_t *parser) {
    printf("ELF Header:\n");
    printf("  Magic:   ");
    for (int i = 0; i < EI_NIDENT; i++) {
        printf("%02x ", parser->elf_header->e_ident[i]);
    }
    printf("\n");
    printf("  Class:                             %s\n", parser->elf_header->e_ident[EI_CLASS] == ELFCLASS64 ? "ELF64" : "ELF32");
    printf("  Data:                              %s\n", parser->elf_header->e_ident[EI_DATA] == ELFDATA2LSB ? "2's complement, little endian" : "2's complement, big endian");
    printf("  Version:                           %d\n", parser->elf_header->e_ident[EI_VERSION]);
    printf("  OS/ABI:                            %d\n", parser->elf_header->e_ident[EI_OSABI]);
    printf("  ABI Version:                       %d\n", parser->elf_header->e_ident[EI_ABIVERSION]);
    printf("  Type:                              %d\n", parser->elf_header->e_type);
    printf("  Machine:                           %d\n", parser->elf_header->e_machine);
    printf("  Version:                           %d\n", parser->elf_header->e_version);
    printf("  Entry point address:               %lx\n", parser->elf_header->e_entry);
    printf("  Start of program headers:          %ld (bytes into file)\n", parser->elf_header->e_phoff);
    printf("  Start of section headers:          %ld (bytes into file)\n", parser->elf_header->e_shoff);
    printf("  Flags:                             %d\n", parser->elf_header->e_flags);
    printf("  Size of this header:               %d (bytes)\n", parser->elf_header->e_ehsize);
    printf("  Size of program headers:           %d (bytes)\n", parser->elf_header->e_phentsize);
    printf("  Number of program headers:         %d\n", parser->elf_header->e_phnum);
    printf("  Size of section headers:           %d (bytes)\n", parser->elf_header->e_shentsize);
    printf("  Number of section headers:         %d\n", parser->elf_header->e_shnum);
    printf("  Section header string table index: %d\n", parser->elf_header->e_shstrndx);
}

void dump_program_header(elf_parser_t *parser) {
    printf("Program Headers:\n");
    printf("  Type           Offset             VirtAddr           PhysAddr           FileSiz            MemSiz             Flg Align\n");
    for (int i = 0; i < parser->elf_header->e_phnum; i++) {
        printf("  %-15s 0x%016lx 0x%016lx 0x%016lx 0x%016lx 0x%016lx %c%c%c 0x%lx\n",
               parser->program_header[i].p_type == PT_NULL ? "NULL" :
               parser->program_header[i].p_type == PT_LOAD ? "LOAD" :
               parser->program_header[i].p_type == PT_DYNAMIC ? "DYNAMIC" :
               parser->program_header[i].p_type == PT_INTERP ? "INTERP" :
               parser->program_header[i].p_type == PT_NOTE ? "NOTE" :
               parser->program_header[i].p_type == PT_SHLIB ? "SHLIB" :
               parser->program_header[i].p_type == PT_PHDR ? "PHDR" :
               parser->program_header[i].p_type == PT_TLS ? "TLS" :
               parser->program_header[i].p_type == PT_GNU_EH_FRAME ? "GNU_EH_FRAME" :
               parser->program_header[i].p_type == PT_GNU_STACK ? "GNU_STACK" :
               parser->program_header[i].p_type == PT_GNU_RELRO ? "GNU_RELRO" :
               "UNKNOWN",
               parser->program_header[i].p_offset,
               parser->program_header[i].p_vaddr,
               parser->program_header[i].p_paddr,
               parser->program_header[i].p_filesz,
               parser->program_header[i].p_memsz,
               (parser->program_header[i].p_flags & PF_R) ? 'R' : '-',
               (parser->program_header[i].p_flags & PF_W) ? 'W' : '-',
               (parser->program_header[i].p_flags & PF_X) ? 'X' : '-',
               parser->program_header[i].p_align);
    }
}

void dump_section_header(elf_parser_t *parser) {
    printf("Section Headers:\n");
    printf("  [Nr] Name              Type            Address           Offset            Size              EntSize           Flags  Link  Info  Align\n");
    for (int i = 0; i < parser->elf_header->e_shnum; i++) {
        printf("  [%2d] %-17s %-15s 0x%016lx 0x%016lx 0x%016lx 0x%016lx %c%c%c %5d %5d 0x%lx\n",
               i,
               parser->file_name + parser->section_header[parser->elf_header->e_shstrndx].sh_offset + parser->section_header[i].sh_name,
               parser->section_header[i].sh_type == SHT_NULL ? "NULL" :
               parser->section_header[i].sh_type == SHT_PROGBITS ? "PROGBITS" :
               parser->section_header[i].sh_type == SHT_SYMTAB ? "SYMTAB" :
               parser->section_header[i].sh_type == SHT_STRTAB ? "STRTAB" :
               parser->section_header[i].sh_type == SHT_RELA ? "RELA" :
               parser->section_header[i].sh_type == SHT_HASH ? "HASH" :
               parser->section_header[i].sh_type == SHT_DYNAMIC ? "DYNAMIC" :
               parser->section_header[i].sh_type == SHT_NOTE ? "NOTE" :
               parser->section_header[i].sh_type == SHT_NOBITS ? "NOBITS" :
               parser->section_header[i].sh_type == SHT_REL ? "REL" :
               parser->section_header[i].sh_type == SHT_SHLIB ? "SHLIB" :
               parser->section_header[i].sh_type == SHT_DYNSYM ? "DYNSYM" :
               "UNKNOWN",
               parser->section_header[i].sh_addr,
               parser->section_header[i].sh_offset,
               parser->section_header[i].sh_size,
               parser->section_header[i].sh_entsize,
               (parser->section_header[i].sh_flags & SHF_WRITE) ? 'W' : '-',
               (parser->section_header[i].sh_flags & SHF_ALLOC) ? 'A' : '-',
               (parser->section_header[i].sh_flags & SHF_EXECINSTR) ? 'X' : '-',
               parser->section_header[i].sh_link,
               parser->section_header[i].sh_info,
               parser->section_header[i].sh_addralign);
    }
}

void dump_symbol_table(elf_parser_t *parser) {
    for (int i = 0; i < parser->elf_header->e_shnum; i++) {
        if (parser->section_header[i].sh_type == SHT_SYMTAB) {
            printf("Symbol table '%s' contains %ld entries:\n",
                   parser->file_name + parser->section_header[parser->section_header[i].sh_link].sh_offset,
                   parser->section_header[i].sh_size / parser->section_header[i].sh_entsize);
            printf("  Num:    Value          Size Type    Bind   Vis      Ndx Name\n");
            parser->symbol_table = (Elf64_Sym *) (parser->map_start + parser->section_header[i].sh_offset);
            for (int j = 0; j < parser->section_header[i].sh_size / parser->section_header[i].sh_entsize; j++) {
                printf("  %3d: %016lx %5ld %-7s %-6s %-8s %3d %s\n",
                       j,
                       parser->symbol_table[j].st_value,
                       parser->symbol_table[j].st_size,
                       parser->symbol_table[j].st_info & 0xf == STT_NOTYPE ? "NOTYPE" :
                       parser->symbol_table[j].st_info & 0xf == STT_OBJECT ? "OBJECT" :
                       parser->symbol_table[j].st_info & 0xf == STT_FUNC ? "FUNC" :
                       parser->symbol_table[j].st_info & 0xf == STT_SECTION ? "SECTION" :
                       parser->symbol_table[j].st_info & 0xf == STT_FILE ? "FILE" :
                       parser->symbol_table[j].st_info & 0xf == STT_COMMON ? "COMMON" :
                       parser->symbol_table[j].st_info & 0xf == STT_TLS ? "TLS" :
                       "UNKNOWN",
                       parser->symbol_table[j].st_info >> 4 == STB_LOCAL ? "LOCAL" :
                       parser->symbol_table[j].st_info >> 4 == STB_GLOBAL ? "GLOBAL" :
                       parser->symbol_table[j].st_info >> 4 == STB_WEAK ? "WEAK" :
                       "UNKNOWN",
                       parser->symbol_table[j].st_other == STV_DEFAULT ? "DEFAULT" :
                       parser->symbol_table[j].st_other == STV_INTERNAL ? "INTERNAL" :
                       parser->symbol_table[j].st_other == STV_HIDDEN ? "HIDDEN" :
                       parser->symbol_table[j].st_other == STV_PROTECTED ? "PROTECTED" :
                       "UNKNOWN",
                       parser->symbol_table[j].st_shndx == SHN_UNDEF ? "UND" :
                       parser->symbol_table[j].st_shndx == SHN_ABS ? "ABS" :
                       parser->symbol_table[j].st_shndx == SHN_COMMON ? "COM" :
                       parser->section_header[parser->symbol_table[j].st_shndx].sh_type == SHT_NOBITS ? "BSS" :
                       parser->section_header[parser->symbol_table[j].st_shndx].sh_type == SHT_PROGBITS ? "DATA" :
                       "UNKNOWN",
                       parser->file_name + parser->section_header[parser->section_header[i].sh_link].sh_offset + parser->symbol_table[j].st_name);
            }
            return;
        }
    }
    printf("No symbol table found in %s\n", parser->file_name);
}

void destroy_parser(elf_parser_t *parser) {
    munmap(parser->map_start, lseek(parser->fd, 0, SEEK_END));
    free(parser);
    close(parser->fd);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ELF binary file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    elf_parser_t *parser = malloc(sizeof(elf_parser_t));
    if (parser == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    init_parser(fd, argv[1], parser);
    dump_elf_header(parser);
    dump_program_header(parser);
    dump_section_header(parser);
    dump_symbol_table(parser);
    destroy_parser(parser);

    return 0;
}
