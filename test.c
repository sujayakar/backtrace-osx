#define PACKAGE 1
#define PACKAGE_VERSION 1
#include "bfd.h"
#include "mach-o.h"
#include <stdio.h>
#include <stdlib.h>

static void get_section_name(bfd *abfd, asection *section, void *data) {
  printf("section: %s\n", section->name);
}

int main(int argc, char** argv) {
  if (argc < 3) {
    printf("usage: %s binary section (addr)*\n", argv[0]);
    exit(1);
  }

  bfd_init();
  bfd* abfd = bfd_openr(argv[1], 0);
  if (abfd == NULL) {
    printf("null file\n");
    exit(1);
  }

  // Decompress sections?
  abfd->flags |= BFD_DECOMPRESS;

  if (bfd_check_format(abfd, bfd_archive)) {
    printf("cannot get addresses from archive\n");
    exit(1);
  }

  char **matching;
  if (!bfd_check_format_matches(abfd, bfd_object, &matching)) {
    printf("Format mismatch?\n");
    exit(1);
  }

  char* section_name = argv[2];
  asection *section = bfd_get_section_by_name(abfd, section_name);
  if (section == NULL) {
    bfd_map_over_sections(abfd, get_section_name, NULL);

    printf("Couldn't find section %s\n", section_name);
    exit(1);
  }
  if ((bfd_get_section_flags(abfd, section) & SEC_ALLOC) == 0) {
    printf("sec alloc?\n");
    exit(1);
  }
  bfd_size_type size = bfd_get_section_size(section);

  if ((bfd_get_file_flags(abfd) & HAS_SYMS) == 0) {
    printf("No symbols");
    exit(1);
  }

  long storage = bfd_get_symtab_upper_bound(abfd);
  if (storage == 0) {
    printf("dynamic storage");
    exit(1);
  }
  asymbol **syms = (asymbol**) malloc(storage);
  long symcount = bfd_canonicalize_symtab(abfd, syms);
  if (symcount < 0) {
    printf("Couldn't slurp symtable\n");
    exit(1);
  }

  for (int i = 3; i < argc; i++) {
    char* addr_hex = argv[i];
    bfd_vma pc = bfd_scan_vma(addr_hex, NULL, 16);
    if (pc >= size) {
      printf("Out of bounds address\n");
      exit(1);
    }

    const char* filename;
    const char* functionname;
    unsigned int line = 0;
    unsigned int discriminator = 0;

    int found = bfd_mach_o_find_nearest_line(abfd, syms, section, pc,
                                             &filename, &functionname,
                                             &line, &discriminator);
    /* int found = bfd_find_nearest_line_discriminator(abfd, section, syms, pc, */
    /*                                                 &filename, &functionname, */
    /*                                                 &line, &discriminator); */
    if (!found) {
      printf("not found\n");
      exit(1);
    }
    printf("%s: %s:%s:%d:%d\n", addr_hex, filename, functionname, line, discriminator);
  }
}
