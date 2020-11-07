#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>
#include "winapi2sdl.h"

// ---------------
// HOOKING LIBRARY
// ---------------
typedef struct __attribute__((packed)) RegSet
{
    uintptr_t EDI;
    uintptr_t ESI;
    uintptr_t EBP;
    uintptr_t EBX;
    uintptr_t EDX;
    uintptr_t ECX;
    uintptr_t EAX;
    uintptr_t ESP;
} RegSet;

static void dump_regset(const RegSet *regs)
{
    printf("ESP: %" PRIxPTR "\n", regs->ESP);
    printf("EAX: %" PRIxPTR "\n", regs->EAX);
    printf("ECX: %" PRIxPTR "\n", regs->ECX);
    printf("EDX: %" PRIxPTR "\n", regs->EDX);
    printf("EBX: %" PRIxPTR "\n", regs->EBX);
    printf("EBP: %" PRIxPTR "\n", regs->EBP);
    printf("ESI: %" PRIxPTR "\n", regs->ESI);
    printf("EDI: %" PRIxPTR "\n", regs->EDI);
}

static void hook(void *origin, void *destination) {
    uint8_t *trampoline = mmap(NULL, 128, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint8_t *trampolinep = trampoline;
    *trampolinep++ = 0x54; // PUSH ESP
    *trampolinep++ = 0x50; // PUSH EAX
    *trampolinep++ = 0x51; // PUSH ECX
    *trampolinep++ = 0x52; // PUSH EDX
    *trampolinep++ = 0x53; // PUSH EBX
    *trampolinep++ = 0x55; // PUSH EBP
    *trampolinep++ = 0x56; // PUSH ESI
    *trampolinep++ = 0x57; // PUSH EDI

    *trampolinep++ = 0x54; // PUSH ESP
    *trampolinep++ = 0xB8; // MOV EAX, ...
    for (size_t i = 0; i < 4; i++)
        *trampolinep++ = (uintptr_t)destination >> (i * 8);
    *trampolinep++ = 0xFF; // CALL EAX
    *trampolinep++ = 0xD0;

    *trampolinep++ = 0x5F; // POP EDI
    *trampolinep++ = 0x5E; // POP ESI
    *trampolinep++ = 0x5D; // POP EBP
    *trampolinep++ = 0x5B; // POP EBX
    *trampolinep++ = 0x5A; // POP EDX
    *trampolinep++ = 0x59; // POP ECX
    *trampolinep++ = 0x58; // POP EAX
    *trampolinep++ = 0x5C; // POP ESP
    *trampolinep++ = 0xC3; // RETN

    uint8_t *originp = (uint8_t *)origin;
    *originp++ = 0x68; // PUSH
    for (size_t i = 0; i < 4; i++)
        *originp++ = (uintptr_t)trampoline >> (i * 8);
    *originp++ = 0xC3; // RETN
}

#define HOOK_CALLBACK __attribute__((stdcall))

#define CLOBBER_ALL "edi", "esi", "ebp", "ebx", "edx", "ecx", "eax", "memory"

// -----
// HOOKS
// -----
static HOOK_CALLBACK void Main_40168C(RegSet *UNUSED(regs)) {
    const char *cmdp = KERNEL32_GetCommandLineA();
    if (*cmdp == '"') {
        // Quoted string -> Advance until quotes closed
        cmdp++;
        while (*cmdp != '\0' && *cmdp != '"')
            cmdp++;
        if (*cmdp == '"')
            cmdp++;
    } else {
        // Unquoted string -> Advance until whitespace
        while (*cmdp != '\0' && *cmdp > ' ')
            cmdp++;
    }
    // Advance whitespace after first argument
    while (*cmdp != '\0' && *cmdp <= ' ')
        cmdp++;

    // Call into entry
    asm ("movl %0, %%eax\n\t"
         "movl $0x401131, %%esi\n\t"
         "call *%%esi\n\t"
         : : "g"(cmdp) : CLOBBER_ALL);

    // This is buggy in HEAVEN7W and calls ExitProcess(return address of entrypoint),
    // which is basically a "random" value, so just return whatever we want here
    KERNEL32_ExitProcess(0x12345678);
}

static HOOK_CALLBACK void PumpMessages_4016CC(RegSet *regs) {
    regs->EAX = 0;
    MSG msg;
    while (USER32_PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE) != 0)
    {
        if (msg.message == WM_KEYDOWN)
            regs->EAX = msg.wParam;
        else if (msg.message == WM_SYSKEYDOWN)
            regs->EAX = msg.wParam | 0x10000;
        else if (msg.message == WM_QUIT)
        {
            regs->EAX = 0xFFFFFFFF;
            return;
        }
        USER32_DispatchMessageA(&msg);
    }
    if (*((uint8_t *)0x429880) == 1)
        regs->EAX = 0xFFFFFFFF;
}

static void *GetSomething_40C4E4_Impl() {
    return *(void **)0x42A404;
}

static HOOK_CALLBACK void GetSomething_40C4E4(RegSet *regs) {
    regs->EBP = (uintptr_t)GetSomething_40C4E4_Impl();
}

static intptr_t WindowProc_40172F_Impl(void *hwnd, uint32_t msg, uintptr_t wParam, intptr_t lParam) {
    void *p = GetSomething_40C4E4_Impl();
    if (*((uint8_t *)p + 0x18) & 1)
        USER32_SetCursor(NULL);

    if (msg == WM_CREATE) {
        *((uint8_t *)0x429880) = 0;
        return 0;
    }
    if (msg == WM_DESTROY) {
        *((uint8_t *)0x429880) = 1;
        return 0;
    }

    return USER32_DefWindowProcA(hwnd, msg, wParam, lParam);
}

static HOOK_CALLBACK void WindowProc_40172F(RegSet *regs) {
    void *hwnd = *(void **)(regs->ESP + 4);
    uint32_t message = *(uint32_t *)(regs->ESP + 8);
    uintptr_t wParam = *(uint32_t *)(regs->ESP + 12);
    intptr_t lParam = *(uint32_t *)(regs->ESP + 16);
    *(uint32_t *)(regs->ESP + 16) = *(uint32_t *)regs->ESP; // Fixup return
    regs->ESP += 16; // Consume args

    regs->EAX = WindowProc_40172F_Impl(hwnd, message, wParam, lParam);
}

static HOOK_CALLBACK void FreeMemory_4017A9_Impl(void *ptr) {
    if (ptr != NULL)
        KERNEL32_GlobalFree(ptr);
}

static HOOK_CALLBACK void FreeMemory_4017A9(RegSet *regs) {
    void *ptr = (void *)regs->EAX;
    FreeMemory_4017A9_Impl(ptr);
}

// --------
// LAUNCHER
// --------
#define IMAGEBASE 0x400000
#define IMAGESIZE 0x2E000
#define ENTRYPOINT 0x42C8A0

static const enum ExecMode {
    ExecMode_Shim,
    ExecMode_UnpackAndValgrindHack,
    ExecMode_UnpackAndHook
} ExecMode = ExecMode_UnpackAndHook;

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

    if (ExecMode == ExecMode_Shim) {
        ((entrypoint_t)ENTRYPOINT)();
    } else {
        // Let UPX unpack the main program and return back to main
        static uint32_t JUMP_TO_OEP_ADDR = 0x2C9F8;
        uint8_t oldi = *(image + JUMP_TO_OEP_ADDR);
        *(image + JUMP_TO_OEP_ADDR) = 0xC3; // RET on jump to OEP
        ((entrypoint_t)ENTRYPOINT)();
        *(image + JUMP_TO_OEP_ADDR) = oldi;

        if (ExecMode == ExecMode_UnpackAndValgrindHack)
        {
            // Valgrind does not recognize the following weird instruction in HEAVEN7W:
            // 0x0040B804: 2E 8B2D 00A44200 MOV EBP,DWORD PTR CS:[42A400]
            // The problem seems to be that Valgrind does not support the CS segment prefix (2E)
            // Patching it out seems harmless and allows it to run the rest of the program
            *(uint8_t *)0x40B804 = 0x90; // NOP
        } else if (ExecMode == ExecMode_UnpackAndHook) {
            hook((void *)0x40168C, Main_40168C);
            hook((void *)0x40C4E4, GetSomething_40C4E4);
            hook((void *)0x4016CC, PumpMessages_4016CC);
            hook((void *)0x40172F, WindowProc_40172F);
            hook((void *)0x4017A9, FreeMemory_4017A9);
        }

        // Jump back to the main program
        ((entrypoint_t)(IMAGEBASE+JUMP_TO_OEP_ADDR))();
    }

    return EXIT_SUCCESS;
}
