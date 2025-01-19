#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include "winapi2sdl.h"

// --------
// LAUNCHER
// --------
#define IMAGEBASE 0x400000
#define IMAGESIZE 0x2E000
#define ENTRYPOINT 0x42C8A0

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

    ((entrypoint_t)ENTRYPOINT)();

    return EXIT_SUCCESS;
}
