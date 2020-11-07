#ifndef WINAPI2SDL_H
#define WINAPI2SDL_H

#include <stdbool.h>

// This attribute needs to be applied to all calls from HEAVEN7 application code back to our code
// It sets stdcall because this is the calling convention used for Win32 APIs,
// and force_align_arg_pointer because if some libraries (SDL mostly) uses SSE code,
// we need to make sure the stack is properly re-aligned after HEAVEN7 de-aligned it,
// or the SSE instructions will cause a crash due to an unaligned load/store
#define API_CALLBACK __attribute__((stdcall)) __attribute__((force_align_arg_pointer))

API_CALLBACK void KERNEL32_ExitProcess(uint32_t exitcode);
API_CALLBACK void *KERNEL32_LoadLibraryA(const char *libraryName);
API_CALLBACK void *KERNEL32_GetProcAddress(void *module, const char *procName);

bool WinAPI2SDL_Init(int argc, char *argv[]);
void WinAPI2SDL_Quit();

#endif
