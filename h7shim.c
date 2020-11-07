#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include "winapi2sdl.h"

#define IMAGEBASE 0x400000
#define IMAGESIZE 0x2E000
#define ENTRYPOINT 0x42C8A0

static const bool valgrind_hack = false;

typedef void (*entrypoint_t)(void);

int main(int argc, char *argv[]) {
    if (!WinAPI2SDL_Init(argc, argv))
        return EXIT_FAILURE;
    atexit(WinAPI2SDL_Quit);

    uint8_t *image = mmap((void *)IMAGEBASE, IMAGESIZE, PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (image == MAP_FAILED) {
        fprintf(stderr, "ERROR: Failed to map HEAVEN7 executable memory.\n");
        return EXIT_FAILURE;
    }

    FILE *h7exe = fopen("HEAVEN7W.EXE", "rb");
    if (h7exe == NULL) {
        fprintf(stderr, "ERROR: Failed to open HEAVEN7 executable.\n");
        return EXIT_FAILURE;
    }
    size_t r1 = fread(image, 1, 0x400, h7exe);
    size_t r2 = fread(image+0x1D000, 1, 0xFA00, h7exe);
    size_t r3 = fread(image+0x2D000, 1, 0x200, h7exe);
    if (r1+r2+r3 != 0x10000) {
        fprintf(stderr, "ERROR: Failed to read HEAVEN7 executable image.\n");
        fclose(h7exe);
        return EXIT_FAILURE;
    }
    fclose(h7exe);

    // Set up symbols used by the unpacker to find the rest of the symbols
    *((void **)(image + 0x2D078)) = KERNEL32_LoadLibraryA;
    *((void **)(image + 0x2D07C)) = KERNEL32_GetProcAddress;
    *((void **)(image + 0x2D080)) = KERNEL32_ExitProcess;

    if (mprotect(image, IMAGESIZE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        fprintf(stderr, "ERROR: Failed to change HEAVEN7 executable memory protection.\n");
    }

    if (!valgrind_hack) {
        ((entrypoint_t)ENTRYPOINT)();
    } else {
        // Let UPX unpack the main program and return back to main
        static uint32_t JUMP_TO_OEP_ADDR = 0x2C9F8;
        uint8_t oldi = *(image + JUMP_TO_OEP_ADDR);
        *(image + JUMP_TO_OEP_ADDR) = 0xC3; // RET on jump to OEP
        ((entrypoint_t)ENTRYPOINT)();
        *(image + JUMP_TO_OEP_ADDR) = oldi;
        // Valgrind does not recognize the following weird instruction in HEAVEN7W:
        // 0x0040B804: 2E 8B2D 00A44200 MOV EBP,DWORD PTR CS:[42A400]
        // The problem seems to be that Valgrind does not support the CS segment prefix (2E)
        // Patching it out seems harmless and allows it to run the rest of the program
        *(char *)0x40B804 = 0x90; // NOP
        // Jump back to the main program
        ((entrypoint_t)(IMAGEBASE+JUMP_TO_OEP_ADDR))();
    }

    return EXIT_SUCCESS;
}
