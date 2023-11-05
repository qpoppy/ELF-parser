
#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define LASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "Assertion failed: %s\n", message); \
            exit(EXIT_FAILURE); \
        } \
    } while (0)

#define CLR "\x1B[0m"

typedef struct {
    void *program_buffer;
    size_t program_size;
    void *string_table_buffer;
    void *symbol_table_buffer;
    Elf64_Ehdr *elf_header;
    Elf64_Sym *symbol_table;
    Elf64_Phdr *program_header;
    Elf64_Shdr *section_header;
} elf_parser_t;

void init_parser(elf_parser_t *parser, const char *filename);
void destroy_parser(elf_parser_t *parser);

void dump_elf_header(const elf_parser_t *parser);
void dump_string_table(const elf_parser_t *parser);
void dump_symbol_table(const elf_parser_t *parser);
void dump_program_header(const elf_parser_t *parser);
void dump_section_header(const elf_parser_t *parser);

const char *dump_elf_flag(uint32_t flag);
const char *dump_program_type(uint32_t type);
const char *dump_program_flag(uint32_t flag);
const char *dump_section_type(uint32_t type);
const char *dump_section_flag(uint64_t flag);
const char *dump_symbol_bind(uint8_t bind);
const char *dump_symbol_type(uint8_t type);
const char *dump_symbol_visibility(uint8_t visibility);

size_t get_elf_size(const char *filename);
bool validate_elf(const char *filename);

#endif
