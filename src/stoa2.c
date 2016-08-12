// Wow, libbfd is obnoxious as fuck with its autoconf bullshit
#define PACKAGE 1
#define PACKAGE_VERSION 1

#include "bfd.h"
#include "mach-o.h"
#include <stdlib.h>

// print_dwarf_symbol(.., slide, addr)
// resolve(addr - (options.load_address - context.intended_addr))

typedef struct resolution_ctx {
  bfd *abfd;
  asymbol **symtab;
  asection *section;
  uint64_t loadaddr;
  uint64_t slide;
} resolution_ctx;

int stoa2_initialize(char* binary_path, char* section_name, uint64_t loadaddr, uint64_t slide, resolution_ctx *out) {
  bfd* abfd;
  asymbol **syms;
  int result = -1;

  abfd = bfd_openr(binary_path, 0);
  if (abfd == NULL)
    goto CLEANUP;

  // Decompress sections
  abfd->flags |= BFD_DECOMPRESS;
  if (bfd_check_format(abfd, bfd_archive))
    goto CLEANUP;

  char **matching;
  if (!bfd_check_format_matches(abfd, bfd_object, &matching))
    goto CLEANUP;

  asection* section = bfd_get_section_by_name(abfd, section_name);
  if (section == NULL)
    goto CLEANUP;

  // Get the symbol table
  if ((bfd_get_file_flags(abfd) & HAS_SYMS) == 0)
    goto CLEANUP;

  long storage = bfd_get_symtab_upper_bound(abfd);
  if (storage == 0)
    goto CLEANUP;

  syms = (asymbol**) malloc(storage);
  if (syms == NULL)
    goto CLEANUP;

  long symcount = bfd_canonicalize_symtab(abfd, syms);
  if (symcount < 0)
    goto CLEANUP;

  out->abfd = abfd;
  out->symtab = syms;
  out->section = section;
  out->loadaddr = loadaddr;
  out->slide = slide;
  return 0;

 CLEANUP:
  if (abfd != NULL)
    bfd_close(abfd);
  if (syms != NULL)
    free(syms);
  return -1;
}

void stoa2_destroy(resolution_ctx *ctx) {
  if (ctx->abfd != NULL)
    bfd_close(ctx->abfd);
  if (ctx->symtab != NULL)
    free(ctx->symtab);;
}

int stoa2_resolve(resolution_ctx *ctx, uint64_t addr, char** filename, char** functionname, unsigned int* lineno) {
  bfd_vma pc = (bfd_vma) (addr - ctx->loadaddr);
  if (pc >= bfd_get_section_size(ctx->section)) {
    return -1;
  }
  // wtf is this?
  unsigned int discriminator;
  int found = bfd_mach_o_find_nearest_line(ctx->abfd, ctx->symtab, ctx->section, pc,
                                           filename, functionname, lineno, &discriminator);
  /* int found =  bfd_find_nearest_line_discriminator(ctx->abfd, ctx->section, ctx->symtab, pc, */
  /*                                                  filename, functionname, */
  /*                                                  lineno, &discriminator); */
  if (!found) {
    return -1;
  }
  return 0;
}
