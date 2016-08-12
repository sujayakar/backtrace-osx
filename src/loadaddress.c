#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

uint64_t addr_slide() {
    const struct segment_command_64* cmd = getsegbyname("__TEXT");
    char executable_path[1024];
    uint32_t size = sizeof(executable_path);
    if (_NSGetExecutablePath(executable_path, &size) != 0) {
        return 0;
    }
    uint32_t dyld_count = _dyld_image_count();
    for (uint32_t i = 0; i < dyld_count; i++) {
      const char* image_name = _dyld_get_image_name(i);
      if (image_name == NULL) {
        break;
      }
      if (strncmp(image_name, executable_path, 1024) == 0) {
        return (uint64_t) _dyld_get_image_vmaddr_slide(i);
      }
    }
    printf("Couldn't get slide!\n");
    exit(1);
}

uint64_t base_address() {
    const struct segment_command_64* cmd = getsegbyname("__TEXT");
    if (cmd == NULL) {
      printf("Couldn't get base address\n");
      exit(1);
    }
    return cmd->vmaddr;
}

uint64_t load_address() {
    return base_address() + addr_slide();
}

int get_executable_path(char* buf, size_t buflen) {
    // _NSGetExecutablePath uses the `bufsize` argument for signaling
    // how much space it needs if the buffer given is too small.
    uint32_t bufsize = (uint32_t) buflen;
    return _NSGetExecutablePath(buf, &bufsize);
}
