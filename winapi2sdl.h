#ifndef WINAPI2SDL_H
#define WINAPI2SDL_H

#include <stdbool.h>

// This attribute needs to be applied to all calls from HEAVEN7 application code back to our code
// It sets stdcall because this is the calling convention used for Win32 APIs,
// and force_align_arg_pointer because if some libraries (SDL mostly) uses SSE code,
// we need to make sure the stack is properly re-aligned after HEAVEN7 de-aligned it,
// or the SSE instructions will cause a crash due to an unaligned load/store
#define API_CALLBACK __attribute__((stdcall)) __attribute__((force_align_arg_pointer))

API_CALLBACK void *DSOUND_SoundBufferImpl_GetStatus(void *cominterface, uint32_t *status);
API_CALLBACK void *DSOUND_SoundBufferImpl_Restore(void *cominterface);
API_CALLBACK void *DSOUND_SoundBufferImpl_Lock(
    void *cominterface,
    uint32_t dwOffset, uint32_t dwBytes,
    void **ppvAudioPtr1, uint32_t *pdwAudioBytes1,
    void **ppvAudioPtr2, uint32_t *pdwAudioBytes2,
    uint32_t dwFlags);
API_CALLBACK void *DSOUND_SoundBufferImpl_Unlock(
    void *cominterface, void *pvAudioPtr1, uint32_t dwAudioBytes1,
    void *pvAudioPtr2, uint32_t dwAudioBytes2);
API_CALLBACK void *DSOUND_SoundBufferImpl_SetFormat(void *cominterface, void *format);
API_CALLBACK void *DSOUND_SoundBufferImpl_Play(
         void *cominterface,
         uint32_t dwReserved1,
         uint32_t dwPriority,
         uint32_t dwFlags);
API_CALLBACK void *DSOUND_SoundBufferImpl_GetCurrentPosition(
    void *cominterface, uint32_t *pdwCurrentPlayCursor, uint32_t *pdwCurrentWriteCursor);
API_CALLBACK void *DSOUND_SoundBufferImpl_Stop(void *cominterface);
API_CALLBACK void *DSOUND_SoundBufferImpl_Release(void *cominterface);
API_CALLBACK void *DSOUND_CreateSoundBuffer(
    void *cominterface, void *buffer_desc, void **ppdsb, void *unk);
API_CALLBACK void *DSOUND_SetCooperativeLevel(
    void *cominterface, void *hwnd, uint32_t flags);
API_CALLBACK void *DSOUND_Release(void *cominterface);
API_CALLBACK void *DSOUND_DirectSoundCreate(
   void *guid, void **lpds, void *unkouter);

API_CALLBACK void *KERNEL32_GlobalAlloc(uint32_t flags, uint32_t memsize);
API_CALLBACK void *KERNEL32_GlobalFree(void *ptr);
API_CALLBACK void *KERNEL32_CreateThread(
      void *lpThreadAttributes, uint32_t dwStackSize, void *lpStartAddress,
      void *lpParameter, uint32_t dwCreationFlags, uint32_t *lpThreadId
);
API_CALLBACK uint32_t KERNEL32_SetThreadPriority(void *thread, int priority);
API_CALLBACK uint32_t KERNEL32_TerminateThread(void *thread, uint32_t exitCode);
API_CALLBACK uint32_t KERNEL32_CloseHandle(void *object);
API_CALLBACK void KERNEL32_InitializeCriticalSection(void *pcs);
API_CALLBACK void KERNEL32_EnterCriticalSection(void *pcs);
API_CALLBACK void KERNEL32_LeaveCriticalSection(void *pcs);
API_CALLBACK void KERNEL32_DeleteCriticalSection(void *pcs);
API_CALLBACK char *KERNEL32_GetCommandLineA(void);
API_CALLBACK void *KERNEL32_GetModuleHandleA(const char *moduleName);
API_CALLBACK void KERNEL32_ExitProcess(uint32_t exitcode);
API_CALLBACK void KERNEL32_Sleep(uint32_t timems);
API_CALLBACK void *KERNEL32_LoadLibraryA(const char *libraryName);
API_CALLBACK void *KERNEL32_GetProcAddress(void *module, const char *procName);

typedef intptr_t (*DialogProc)(void *hdlg, uint32_t msg, uintptr_t wparam, intptr_t lparam);
API_CALLBACK void *USER32_RegisterClassA(const void *wndClass);
API_CALLBACK void *USER32_CreateWindowExA(
    uint32_t exStyle, const char *className, const char *windowName, uint32_t style,
    int x, int y, int width, int height,
    void *hwndParent, void *menu, void *instance, void *pparam);
API_CALLBACK uint32_t USER32_ShowWindow(void *hwnd, uint32_t cmdshow);
API_CALLBACK void USER32_DefWindowProcA(void *hwnd, uint32_t msg,
    uintptr_t wparam, intptr_t lparam);
API_CALLBACK uint32_t USER32_PeekMessageA(
      void *msg, void *hWnd,
      uint32_t msgFilterMin, uint32_t msgFilterMax,
      uint32_t removeMsg);
API_CALLBACK void USER32_DispatchMessageA(const void *msg);
API_CALLBACK uint32_t USER32_DestroyWindow(void *hwnd);
API_CALLBACK uint32_t USER32_ClientToScreen(void *hwnd, void *point);
API_CALLBACK uint32_t USER32_GetClientRect(void *hwnd, void *rect);
API_CALLBACK uint32_t USER32_DialogBoxIndirectParamA(
    void *instance, void *dialogTemplate,
    void *hwndParent, DialogProc dialogFunc, void *initParam);
API_CALLBACK intptr_t USER32_SendDlgItemMessageA(void *hdlg,
    int controlid, uint32_t msg, uintptr_t wparam, intptr_t lparam);
API_CALLBACK uint32_t USER32_EndDialog(void *hdlg, intptr_t result);
API_CALLBACK int USER32_MessageBoxA(void *hwnd, const char *text, const char *caption, uint32_t type);
API_CALLBACK uint32_t USER32_OffsetRect(void *rect, int dx, int dy);
API_CALLBACK int USER32_GetSystemMetrics(int index);
API_CALLBACK uint32_t USER32_SystemParametersInfoA(
    uint32_t action, uint32_t wparam, void *pparam, uint32_t winini);
API_CALLBACK void *USER32_SetCursor(void *cursor);

API_CALLBACK uint32_t WINMM_timeGetTime(void);

API_CALLBACK uint32_t DDRAW_Surface_Release(void *cominterface);
API_CALLBACK void *DDRAW_Surface_Blt(
    void *cominterface, void *rect1, void *surface,
    void *rect2, uint32_t flags, void *bltfx);
API_CALLBACK void *DDRAW_Surface_GetSurfaceDesc(void *cominterface, void *surface_desc);
API_CALLBACK void *DDRAW_Surface_IsLost(void *cominterface);
API_CALLBACK void *DDRAW_Surface_Restore(void *cominterface);
API_CALLBACK void *DDRAW_Surface_Lock(void *cominterface, void *rect, void *surface_desc, uint32_t flags, void *event);
API_CALLBACK void *DDRAW_Surface_SetClipper(void *cominterface, void *clipper);
API_CALLBACK void *DDRAW_Surface_Unlock(void *cominterface, void *rect);
API_CALLBACK uint32_t DDRAW_Clipper_Release(void *cominterface);
API_CALLBACK void *DDRAW_Clipper_SetHWnd(void *cominterface, uint32_t flags, void *hwnd);
API_CALLBACK uint32_t DDRAW_Release(void *cominterface);
API_CALLBACK void *DDRAW_CreateClipper(void *cominterface, uint32_t flags, void **clipper, void *outer);
API_CALLBACK void *DDRAW_CreateSurface(
    void *cominterface, void *surface_desc, void **surface, void *outer);
API_CALLBACK void *DDRAW_RestoreDisplayMode(void *cominterface);
API_CALLBACK void *DDRAW_SetCooperativeLevel(
    void *cominterface, void *hwnd, uint32_t flags);
API_CALLBACK void *DDRAW_SetDisplayMode(void *cominterface,
    uint32_t width, uint32_t height, uint32_t bpp);
API_CALLBACK void *DDRAW_DirectDrawCreate(
    void *guid, void **lpdd, void *unkouter);

bool WinAPI2SDL_Init(int argc, char *argv[]);
void WinAPI2SDL_Quit();

#endif
