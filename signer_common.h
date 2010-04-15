#ifndef __SIGNER__
#define __SIGNER__
#include <sys/types.h>
#include <sys/elf32.h>

int get_section_index (char *, Elf32_Shdr *, Elf32_Ehdr *, char *);
int get_section_entries(int, Elf32_Shdr **, Elf32_Ehdr);
int get_section_data(int, int, void **, int);
void *get_section_entry (int, Elf32_Shdr *);
int get_program_entries(int, Elf32_Phdr **, Elf32_Ehdr);
int write_signed(int, int, Elf32_Shdr *, Elf32_Phdr *,
    Elf32_Ehdr *, char *, char *);
int append_string_table (char **, Elf32_Shdr *, char *);
void add_section_entry (Elf32_Shdr *, Elf32_Ehdr *, int, char *);
void gen_hash (void *, int, unsigned char*);
char *issue_cert(FILE *, char *cname, int days);
int is_elf(Elf32_Ehdr *);
void error();
#endif
