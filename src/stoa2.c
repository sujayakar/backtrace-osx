// Wow, libbfd is obnoxious as fuck with its autoconf bullshit
#define PACKAGE 1
#define PACKAGE_VERSION 1

#include "bfd.h"
#include "mach-o.h"
#include <stdlib.h>

int stoa2_resolve(char* binary_path, char* addr_hex, char** filename, char** functionname, unsigned int* lineno) {
  bfd* abfd;
  asection* section;
  asymbol **syms;
  int result = 0;

  abfd = bfd_openr(binary_path, 0);
  if (abfd == NULL) {
    goto CLEANUP;
  }

  // Decompress sections
  abfd->flags |= BFD_DECOMPRESS;
  if (bfd_check_format(abfd, bfd_archive)) {
    goto CLEANUP;
  }
  char **matching;
  if (!bfd_check_format_matches(abfd, bfd_object, &matching)) {
    goto CLEANUP;
  }

  // Get the .text section
  char* section_name = ".text";
  section = bfd_get_section_by_name(abfd, section_name);
  if (section == NULL) {
    goto CLEANUP;
  }
  if ((bfd_get_section_flags(abfd, section) & SEC_ALLOC) == 0) {
    goto CLEANUP;
  }
  // Get the symbol table
  if ((bfd_get_file_flags(abfd) & HAS_SYMS) == 0) {
    goto CLEANUP;
  }

  long storage = bfd_get_symtab_upper_bound(abfd);
  if (storage == 0) {
    goto CLEANUP;
  }
  syms = (asymbol**) malloc(storage);
  if (syms == NULL) {
    goto CLEANUP;
  }
  long symcount = bfd_canonicalize_symtab(abfd, syms);
  if (symcount < 0) {
    goto CLEANUP;
  }

  // Try to resolve the symbol
  bfd_size_type size = bfd_get_section_size(section);
  bfd_vma pc = bfd_scan_vma(addr_hex, NULL, 16);
  if (pc >= size) {
    goto CLEANUP;
  }

  // wtf is this?
  unsigned int discriminator;
  result = bfd_find_nearest_line_discriminator(abfd, section, syms, pc,
                                               filename, functionname,
                                               lineno, &discriminator);

 CLEANUP:
  if (abfd != NULL) {
    bfd_close(abfd);
    abfd = NULL;
  }
  if (syms != NULL) {
    free(syms);
  }
  return result;
}
