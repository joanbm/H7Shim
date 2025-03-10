#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <SDL.h>
#include "winapi2sdl.h"

#define SETTING_RESOLUTION 3 // 0 = 320x240, 1 = 512x384, 2 = 640x480, 3 = 800x600
// But actually the values are: 0 = 320x176, 1 = 512x280, 2 = 640x352, 3 = 800x440
#define SETTING_TRACER 0 // 0 = 1x1, 1 = 2x2, 2 = 4x4
#define SETTING_SOUND 0 // 0 = 44 Khz, 1 = 22 Khz, 2 = Disabled
#define SETTING_WINDOWED 0 // 0 or 1
#define SETTING_NOTEXT 0 // 0 or 1
#define SETTING_LOOP 0 // 0 or 1

static const bool resolution_hack = false;
#define SPEEDUP_FACTOR 1

#if 0
#define LOG_EMULATED() printf("[!] %s EMULATED!\n", __func__)
#else
#define LOG_EMULATED() do { } while(0)
#endif

typedef struct SymbolTable
{
    const char *symbolName;
    void *symbol;
} SymbolTable;

typedef struct LibraryTable
{
    const char *libraryName;
    const SymbolTable *symbolTable;
} LibraryTable;

#define MAKE_SYMBOL_ORDINAL(ord) ((char *)(uint32_t)(ord))

static const LibraryTable *GLOBAL_LIBRARY_TABLE;

// ------
// DSOUND
// ------

typedef struct DSound_SoundBufferImpl_Object
{
    const void *vtable;

    bool is_primary;
    uint8_t *audio_buffer;
    uint32_t audio_buffer_size;
    bool audio_playing;
    uint32_t audio_playpos;
} DSound_SoundBufferImpl_Object;

API_CALLBACK void *DSOUND_SoundBufferImpl_GetStatus(void *cominterface, uint32_t *status)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(status != NULL);

    *status = DSBSTATUS_PLAYING | DSBSTATUS_LOOPING;
    return 0;
}

API_CALLBACK void *DSOUND_SoundBufferImpl_Restore(void *cominterface)
{
    // This is never called in practice since our GetStatus does never return
    // status = 2 (DSBSTATUS_BUFFERLOST) since there isn't a SDL equivalent
    LOG_EMULATED();

    assert(cominterface != NULL);

    return 0;
}

API_CALLBACK void *DSOUND_SoundBufferImpl_Lock(
    void *cominterface,
    uint32_t dwOffset, uint32_t dwBytes,
    void **ppvAudioPtr1, uint32_t *pdwAudioBytes1,
    void **UNUSED(ppvAudioPtr2), uint32_t *UNUSED(pdwAudioBytes2),
    uint32_t UNUSED(dwFlags))
{
    LOG_EMULATED();

    assert(cominterface != NULL);

    SDL_LockAudio();

    DSound_SoundBufferImpl_Object *bufferobj = (DSound_SoundBufferImpl_Object *)cominterface;
    assert(!bufferobj->is_primary);
    assert(dwOffset <= bufferobj->audio_buffer_size);
    assert(dwBytes <= bufferobj->audio_buffer_size);
    assert(dwOffset + dwBytes <= bufferobj->audio_buffer_size);
    if (bufferobj->audio_playing) {
        assert(dwOffset > bufferobj->audio_playpos ||
               (dwOffset + dwBytes <= bufferobj->audio_playpos));
    }

    *ppvAudioPtr1 = &bufferobj->audio_buffer[dwOffset];
    *pdwAudioBytes1 = dwBytes;

    return NULL;
}

API_CALLBACK void *DSOUND_SoundBufferImpl_Unlock(
    void *cominterface, void *UNUSED(pvAudioPtr1), uint32_t UNUSED(dwAudioBytes1),
    void *UNUSED(pvAudioPtr2), uint32_t UNUSED(dwAudioBytes2))
{
    LOG_EMULATED();
    assert(cominterface != NULL);
    SDL_UnlockAudio();

    return NULL;
}

API_CALLBACK void *DSOUND_SoundBufferImpl_SetFormat(void *cominterface, void *format)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(format != NULL);

    return 0;
}

API_CALLBACK void *DSOUND_SoundBufferImpl_Play(
         void *cominterface,
         uint32_t UNUSED(dwReserved1),
         uint32_t UNUSED(dwPriority),
         uint32_t UNUSED(dwFlags))
{
    LOG_EMULATED();
    assert(cominterface != NULL);

    DSound_SoundBufferImpl_Object *bufferobj = (DSound_SoundBufferImpl_Object *)cominterface;
    assert(!bufferobj->is_primary);
    bufferobj->audio_playing = true;
    bufferobj->audio_playpos = 0;
    SDL_PauseAudio(0);

    return 0;
}

API_CALLBACK void *DSOUND_SoundBufferImpl_GetCurrentPosition(
    void *cominterface, uint32_t *pdwCurrentPlayCursor, uint32_t *pdwCurrentWriteCursor)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(pdwCurrentPlayCursor != NULL);
    assert(pdwCurrentWriteCursor != NULL);

    DSound_SoundBufferImpl_Object *bufferobj = (DSound_SoundBufferImpl_Object *)cominterface;
    assert(!bufferobj->is_primary);
    *pdwCurrentPlayCursor = bufferobj->audio_playpos;
    *pdwCurrentWriteCursor = *pdwCurrentPlayCursor; // Don't matter

    return 0;
}

API_CALLBACK void *DSOUND_SoundBufferImpl_Stop(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);

    DSound_SoundBufferImpl_Object *bufferobj = (DSound_SoundBufferImpl_Object *)cominterface;
    assert(!bufferobj->is_primary);
    bufferobj->audio_playing = false;
    bufferobj->audio_playpos = 0;
    SDL_PauseAudio(0);

    return 0;
}

API_CALLBACK void *DSOUND_SoundBufferImpl_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    DSound_SoundBufferImpl_Object *bufferobj = (DSound_SoundBufferImpl_Object *)cominterface;
    if (!bufferobj->is_primary) {
        SDL_CloseAudio();
    }
    free(bufferobj->audio_buffer);
    free(bufferobj);

    return 0;
}

static const void *DSound_SoundBufferImpl_VTABLE[256] = {
    [0x24/4] = DSOUND_SoundBufferImpl_GetStatus,
    [0x50/4] = DSOUND_SoundBufferImpl_Restore,
    [0x2C/4] = DSOUND_SoundBufferImpl_Lock,
    [0x4C/4] = DSOUND_SoundBufferImpl_Unlock,
    [0x38/4] = DSOUND_SoundBufferImpl_SetFormat,
    [0x30/4] = DSOUND_SoundBufferImpl_Play,
    [0x10/4] = DSOUND_SoundBufferImpl_GetCurrentPosition,
    [0x48/4] = DSOUND_SoundBufferImpl_Stop,
    [0x8/4] = DSOUND_SoundBufferImpl_Release,
};

static void AudioCallback(void *userdata, Uint8 *stream, int len)
{
    DSound_SoundBufferImpl_Object *bufferobj = (DSound_SoundBufferImpl_Object *)userdata;

    uint32_t stream_pos = 0, stream_len = (uint32_t)len;
    assert(stream_len < bufferobj->audio_buffer_size);

    if (bufferobj->audio_playing) {
        for (size_t i = 0; i < 2; i++) { // Drain twice to handle circular buffer wraparound
            uint32_t buffer_avail = bufferobj->audio_buffer_size - bufferobj->audio_playpos;
            uint32_t take = stream_len < buffer_avail ? stream_len : buffer_avail;

            memcpy(stream + stream_pos, bufferobj->audio_buffer + bufferobj->audio_playpos, take);
            bufferobj->audio_playpos += take;
            if (bufferobj->audio_playpos == bufferobj->audio_buffer_size)
                bufferobj->audio_playpos = 0;
            stream_pos += take;
            stream_len -= take;
        }
    }

    memset(stream + stream_pos, 0, stream_len);
}

API_CALLBACK void *DSOUND_CreateSoundBuffer(
    void *cominterface, void *buffer_desc, void **ppdsb, void *unk)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(buffer_desc != NULL);
    assert(ppdsb != NULL);
    assert(unk == NULL);

    bool is_primary_buffer = *(uint32_t *)((uint8_t *)buffer_desc + 4) & 1;
    uint32_t buffer_size = *(uint32_t *)((uint8_t *)buffer_desc + 8);
    void *waveformatex = *(void **)((uint8_t *)buffer_desc + 16);
    uint32_t raw_freq = waveformatex != NULL ? *(uint32_t *)((uint8_t *)waveformatex + 4) : 0;
    assert(raw_freq < INT_MAX);
    int freq = (int)raw_freq;

    DSound_SoundBufferImpl_Object *bufferobj = malloc(sizeof(DSound_SoundBufferImpl_Object));
    bufferobj->vtable = DSound_SoundBufferImpl_VTABLE;
    bufferobj->is_primary = is_primary_buffer;
    bufferobj->audio_buffer = !is_primary_buffer ? malloc(buffer_size) : NULL;
    bufferobj->audio_buffer_size = !is_primary_buffer ? buffer_size : 0;
    bufferobj->audio_playing = false;
    bufferobj->audio_playpos = 0;

    if (!bufferobj->is_primary) {
        SDL_AudioSpec wav_spec;
        SDL_memset(&wav_spec, 0, sizeof(wav_spec));
        wav_spec.freq = freq * SPEEDUP_FACTOR;
        wav_spec.format = AUDIO_S16;
        wav_spec.channels = 2;
        // Make the audio buffer small, because H7 uses the consumed audio samples
        // for video timing, so a big audio buffer results in a choppy frame rate
        wav_spec.samples = 512;
        wav_spec.callback = AudioCallback;
        wav_spec.userdata = bufferobj;

        if (SDL_OpenAudio(&wav_spec, NULL) < 0) {
            fprintf(stderr, "Couldn't open SDL audio: %s\n", SDL_GetError());
            exit(EXIT_FAILURE);
        }
    }

    *ppdsb = bufferobj;
    return 0;
}

API_CALLBACK void *DSOUND_SetCooperativeLevel(
    void *cominterface, void *hwnd, uint32_t UNUSED(flags))
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(hwnd != NULL);

    return 0;
}

API_CALLBACK void *DSOUND_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    return 0;
}

static const void *DSOUND_VTABLE[256] = {
    [0x0C/4] = DSOUND_CreateSoundBuffer,
    [0x18/4] = DSOUND_SetCooperativeLevel,
    [0x8/4] = DSOUND_Release,
};

typedef struct DSOUND_Object
{
    const void *vtable;
} DSOUND_Object;

API_CALLBACK void *DSOUND_DirectSoundCreate(
   void *guid, void **lpds, void *unkouter)
{
    LOG_EMULATED();

    assert(guid == NULL);
    assert(lpds != NULL);
    assert(unkouter == NULL);

    static DSOUND_Object DSOUND_NULLOBJECT = { DSOUND_VTABLE };
    *lpds = &DSOUND_NULLOBJECT;
    return 0;
}

static const SymbolTable DSOUND_SYMBOLS[] = {
    { MAKE_SYMBOL_ORDINAL(0x0001), DSOUND_DirectSoundCreate },
    { NULL, NULL }
};

// --------
// KERNEL32
// --------

// **MEMORY**

API_CALLBACK void *KERNEL32_GlobalAlloc(uint32_t flags, uint32_t memsize)
{
    LOG_EMULATED();

    assert(flags == 0);

    return malloc(memsize);
}

API_CALLBACK void *KERNEL32_GlobalFree(void *ptr)
{
    LOG_EMULATED();
    free(ptr);
    return NULL;
}

// **THREADING**

API_CALLBACK void *KERNEL32_CreateThread(
      void *UNUSED(lpThreadAttributes), uint32_t UNUSED(dwStackSize), void *lpStartAddress,
      void *lpParameter, uint32_t UNUSED(dwCreationFlags), uint32_t *UNUSED(lpThreadId)
)
{
    LOG_EMULATED();

    pthread_t *thread = malloc(sizeof(pthread_t));
    pthread_create(thread, NULL, lpStartAddress, lpParameter);
    return thread;
}

API_CALLBACK uint32_t KERNEL32_SetThreadPriority(void *UNUSED(thread), int UNUSED(priority))
{
    LOG_EMULATED();

    return 1;
}

API_CALLBACK uint32_t KERNEL32_TerminateThread(void *thread, uint32_t UNUSED(exitCode))
{
    LOG_EMULATED();

    pthread_t *rthread = (pthread_t *)thread;
    pthread_cancel(*rthread);
    pthread_join(*rthread, NULL);
    return 1;
}

API_CALLBACK uint32_t KERNEL32_CloseHandle(void *object)
{
    LOG_EMULATED();

    pthread_t *thread = (pthread_t *)object;
    free(thread);

    return 1;
}

// **CRITICAL SECTION**

API_CALLBACK void KERNEL32_InitializeCriticalSection(void *pcs)
{
    LOG_EMULATED();

    pthread_mutex_t *mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(mutex, NULL);
    *((pthread_mutex_t **)pcs) = mutex;
}

API_CALLBACK void KERNEL32_EnterCriticalSection(void *pcs)
{
    LOG_EMULATED();

    pthread_mutex_t *mutex = *((pthread_mutex_t **)pcs);
    pthread_mutex_lock(mutex);
}

API_CALLBACK void KERNEL32_LeaveCriticalSection(void *pcs)
{
    LOG_EMULATED();

    pthread_mutex_t *mutex = *((pthread_mutex_t **)pcs);
    pthread_mutex_unlock(mutex);
}

API_CALLBACK void KERNEL32_DeleteCriticalSection(void *pcs)
{
    LOG_EMULATED();

    pthread_mutex_t *mutex = *((pthread_mutex_t **)pcs);
    pthread_mutex_destroy(mutex);
    free(mutex);
}

// **MISC**

static char *COMMANDLINE;

API_CALLBACK char *KERNEL32_GetCommandLineA(void)
{
    LOG_EMULATED();
    // Arguments:
    // (Default: 44Khz sound)
    // n -> No sound
    // s -> 22Khz sound

    // (Default: 1x1 tracer)
    // a -> 4x4 tracer
    // b -> 2x2 tracer

    // (Default: Fullscreen, lowest resolution)
    // w -> Windowed
    // 0123 -> Resolution (higher = better)
    // d -> Double resolution

    // l -> Looping
    // t -> No text
    return COMMANDLINE;
}

API_CALLBACK void *KERNEL32_GetModuleHandleA(const char *moduleName)
{
    LOG_EMULATED();

    assert(moduleName == NULL);
    return NULL; // Theoretically we should actually return IMAGEBASE here,
                 // but it doesn't matter since the code never uses this value
}

API_CALLBACK void KERNEL32_ExitProcess(uint32_t exitcode)
{
    LOG_EMULATED();
    exit((int)exitcode);
}

API_CALLBACK void KERNEL32_Sleep(uint32_t timems)
{
    LOG_EMULATED();

    struct timespec ts;
    ts.tv_sec = (time_t)(timems / 1000);
    ts.tv_nsec = (long)((timems % 1000) * 1000000);
    nanosleep(&ts, NULL);
}

API_CALLBACK void *KERNEL32_LoadLibraryA(const char *libraryName)
{
    LOG_EMULATED();

    assert(libraryName != NULL);

    const LibraryTable *found = NULL;
    for (const LibraryTable *l = GLOBAL_LIBRARY_TABLE; l->libraryName != NULL; l++) {
        if (strcasecmp(l->libraryName, libraryName) == 0) {
            found = l;
            break;
        }
    }

    if (found == NULL) {
        fprintf(stderr, "WARNING: Library '%s' not found.\n", libraryName);
    }

    return (void *)found;
}

static bool symbol_is_ordinal(const char *p)
{
    return (uint32_t)p <= 0xFFFF;
}

static bool symbol_compare(const char *s1, const char *s2)
{
        return
            (symbol_is_ordinal(s1) && symbol_is_ordinal(s2) && s1 == s2) ||
            (!symbol_is_ordinal(s1) && !symbol_is_ordinal(s2) && strcmp(s1, s2) == 0);
}

API_CALLBACK void *KERNEL32_GetProcAddress(void *module, const char *procName)
{
    LOG_EMULATED();

    assert(module != NULL);
    assert(procName != NULL);

    const LibraryTable *lib = (const LibraryTable *)module;
    const SymbolTable *found = NULL;

    for (const SymbolTable *s = lib->symbolTable; s->symbolName != NULL; s++) {
        if (symbol_compare(s->symbolName, procName)) {
            found = s;
            break;
        }
    }

    if (found == NULL) {
        fprintf(stderr, "WARNING: Symbol '");
        fprintf(stderr, symbol_is_ordinal(procName) ? "ORD:%p" : "%s", procName);
        fprintf(stderr, "' not found on library %s.\n", lib->libraryName);
    }

    return found != NULL ? found->symbol : NULL;
}

static const SymbolTable KERNEL32_SYMBOLS[] = {
    { "GetCommandLineA", KERNEL32_GetCommandLineA },
    { "GlobalFree", KERNEL32_GlobalFree },
    { "CreateThread", KERNEL32_CreateThread },
    { "GetModuleHandleA", KERNEL32_GetModuleHandleA },
    { "LeaveCriticalSection", KERNEL32_LeaveCriticalSection },
    { "ExitProcess", KERNEL32_ExitProcess },
    { "InitializeCriticalSection", KERNEL32_InitializeCriticalSection },
    { "SetThreadPriority", KERNEL32_SetThreadPriority },
    { "EnterCriticalSection", KERNEL32_EnterCriticalSection },
    { "CloseHandle", KERNEL32_CloseHandle },
    { "DeleteCriticalSection", KERNEL32_DeleteCriticalSection },
    { "GlobalAlloc", KERNEL32_GlobalAlloc },
    { "Sleep", KERNEL32_Sleep },
    { "TerminateThread", KERNEL32_TerminateThread },
    { "LoadLibraryA", KERNEL32_LoadLibraryA },
    { "GetProcAddress", KERNEL32_GetProcAddress },
    { NULL, NULL }
};

// ------
// USER32
// ------

// **WINDOW**

typedef intptr_t (*WindowProc)(void *hwnd, uint32_t msg, uintptr_t wParam, intptr_t lParam);

typedef struct USER32_WindowClassObject
{
    WindowProc windowProc;
    const char *name;
    struct USER32_WindowClassObject *next;
} USER32_WindowClassObject;

static USER32_WindowClassObject *WINDOWCLASS_HEAD = NULL;
static const char *WINDOWDATA_WINDOWPROC = "WindowProc";

API_CALLBACK void *USER32_RegisterClassA(const void *wndClass)
{
    LOG_EMULATED();

    assert(wndClass != NULL);

    WindowProc windowProc = *(const WindowProc *)((const char *)wndClass + 4);
    const char *className = *(const char **)((const char *)wndClass + 36);

    USER32_WindowClassObject *classobj = malloc(sizeof(USER32_WindowClassObject));
    classobj->windowProc = windowProc;
    classobj->name = className;
    classobj->next = WINDOWCLASS_HEAD;
    WINDOWCLASS_HEAD = classobj;

    return (void *)classobj; // Doesn't really matter
}

API_CALLBACK void *USER32_CreateWindowExA(
    uint32_t UNUSED(exStyle), const char *className, const char *UNUSED(windowName), uint32_t UNUSED(style),
    int UNUSED(x), int UNUSED(y), int UNUSED(width), int UNUSED(height),
    void *UNUSED(hwndParent), void *UNUSED(menu), void *UNUSED(instance), void *UNUSED(pparam))
{
    LOG_EMULATED();

    // Find class
    USER32_WindowClassObject *class = WINDOWCLASS_HEAD;
    while (class != NULL && strcmp(className, class->name) != 0)
        class = class->next;
    assert(class != NULL);

    // Create window and associate windowproc for later calling
    SDL_Window *window = SDL_CreateWindow("HEAVEN7",
                                          SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
                                          123, 123, 0); // Actual size will be set later
    if (window == NULL) {
        fprintf(stderr, "Couldn't open SDL window: %s\n", SDL_GetError());
        exit(EXIT_FAILURE);
    }
    SDL_SetWindowData(window, WINDOWDATA_WINDOWPROC, class->windowProc);

    // Generate window creation event
    class->windowProc((void *)window, WM_CREATE, 0, 0);

    return window;
}

API_CALLBACK uint32_t USER32_ShowWindow(void *hwnd, uint32_t cmdshow)
{
    LOG_EMULATED();

    assert(hwnd != NULL);
    assert(cmdshow == 1);

    return 0;
}

API_CALLBACK intptr_t USER32_DefWindowProcA(void *UNUSED(hwnd), uint32_t UNUSED(msg),
    uintptr_t UNUSED(wParam), intptr_t UNUSED(lParam))
{
    LOG_EMULATED();
    return 0;
}

API_CALLBACK uint32_t USER32_PeekMessageA(
      void *msg, void *UNUSED(hWnd),
      uint32_t UNUSED(msgFilterMin), uint32_t UNUSED(msgFilterMax),
      uint32_t UNUSED(removeMsg))
{
    LOG_EMULATED();

    SDL_Event event;
    while (SDL_PollEvent(&event)) {
        if (event.type == SDL_WINDOWEVENT) {
            // We really only need to send WM_DESTROY window messages here...
            // But we also send any other messge as WM_PAINT so we can keep
            // wndProc busy and receive calls to DefWindowProcA later
            uint32_t message = event.window.event == SDL_WINDOWEVENT_CLOSE
                ? WM_DESTROY : WM_PAINT;

            SDL_Window *window = SDL_GetWindowFromID(event.window.windowID);
            *(void **)((char *)msg + 0) = window;
            *(uint32_t *)((char *)msg + 4) = message;
            *(uintptr_t *)((char *)msg + 8) = 0;
            *(intptr_t *)((char *)msg + 12) = 0;
            return 1;
        } else if (event.type == SDL_QUIT) {
            *(void **)((char *)msg + 0) = NULL;
            *(uint32_t *)((char *)msg + 4) = WM_QUIT;
            *(uintptr_t *)((char *)msg + 8) = 0;
            *(intptr_t *)((char *)msg + 12) = 0;
            return 1;
        }
    }

    return 0;
}

API_CALLBACK void USER32_DispatchMessageA(const void *msg)
{
    LOG_EMULATED();

    SDL_Window *window = (SDL_Window *)*(const void **)((const char *)msg + 0);
    uint32_t message = *(const uint32_t *)((const char *)msg + 4);
    uintptr_t wParam = *(const uintptr_t *)((const char *)msg + 8);
    intptr_t lParam = *(const intptr_t *)((const char *)msg + 12);

    WindowProc windowProc = (WindowProc)SDL_GetWindowData(window, WINDOWDATA_WINDOWPROC);
    windowProc(window, message, wParam, lParam);
}

API_CALLBACK uint32_t USER32_DestroyWindow(void *hwnd)
{
    LOG_EMULATED();

    assert(hwnd != NULL);

    SDL_DestroyWindow((SDL_Window *)hwnd);
    return 1;
}

API_CALLBACK uint32_t USER32_ClientToScreen(void *hwnd, void *point)
{
    LOG_EMULATED();

    assert(hwnd != NULL);
    assert(point != NULL);

    return 1;
}

API_CALLBACK uint32_t USER32_GetClientRect(void *hwnd, void *rect)
{
    LOG_EMULATED();

    assert(hwnd != NULL);
    assert(rect != NULL);

    return 1;
}

// **DIALOG**
API_CALLBACK uint32_t USER32_DialogBoxIndirectParamA(
    void *UNUSED(instance), void *UNUSED(dialogTemplate),
    void *UNUSED(hwndParent), DialogProc dialogFunc, void *UNUSED(initParam))
{
    LOG_EMULATED();

    dialogFunc(NULL, WM_COMMAND, 1 /* Accept button */, 12345);

    if (resolution_hack) {
        ushort *resolutionTable = (ushort *)0x410027;
        SDL_DisplayMode current;
        SDL_GetCurrentDisplayMode(0, &current);
        resolutionTable[SETTING_RESOLUTION*2+0] = current.w;
        resolutionTable[SETTING_RESOLUTION*2+1] = current.h;
    }
    return 1;
}

API_CALLBACK intptr_t USER32_SendDlgItemMessageA(void *UNUSED(hdlg),
    int controlid, uint32_t UNUSED(msg), uintptr_t UNUSED(wParam), intptr_t UNUSED(lParam))
{
    LOG_EMULATED();

    if (controlid == 0x3EB) // Resolution combobox
        return SETTING_RESOLUTION;
    if (controlid == 0x3EC) // Tracer combobox
        return SETTING_TRACER;
    if (controlid == 0x3F1) // Sound combobox
        return SETTING_SOUND;
    if (controlid == 0x3EE) // Windowed checkbox
        return SETTING_WINDOWED;
    if (controlid == 0x3ED) // No text checkbox
        return SETTING_NOTEXT;
    if (controlid == 0x3EF) // Looping checkbox
        return SETTING_LOOP;

    assert(0);
}

API_CALLBACK uint32_t USER32_EndDialog(void *UNUSED(hdlg), intptr_t UNUSED(result))
{
    LOG_EMULATED();

    return 1;
}

// **MISC**

API_CALLBACK int USER32_MessageBoxA(void *hwnd, const char *text, const char *caption, uint32_t UNUSED(type))
{
    LOG_EMULATED();
    SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, caption, text, (SDL_Window *)hwnd);
    return 1;
}

API_CALLBACK uint32_t USER32_OffsetRect(void *rect, int UNUSED(dx), int UNUSED(dy))
{
    LOG_EMULATED();

    assert(rect != NULL);
    return 1;
}

API_CALLBACK int USER32_GetSystemMetrics(int index)
{
    LOG_EMULATED();

    if (index == SM_CXSCREEN)
        return 1920;
    else if (index == SM_CYSCREEN)
        return 1080;
    else if (index == SM_CYSCAPTION)
        return 19;
    else
        assert(0);
}

API_CALLBACK uint32_t USER32_SystemParametersInfoA(
    uint32_t action, uint32_t wParam, void *pparam, uint32_t winini)
{
    LOG_EMULATED();

    assert(action == SPI_GETBORDER);
    assert(wParam == 0);
    assert(pparam != NULL);
    assert(winini == 0);

    *(uint32_t *)pparam = 1;
    return 1;
}

API_CALLBACK void *USER32_SetCursor(void *cursor)
{
    LOG_EMULATED();
    SDL_ShowCursor(cursor != NULL ? SDL_ENABLE : SDL_DISABLE);
    return NULL;
}

static const SymbolTable USER32_SYMBOLS[] = {
    { "CreateWindowExA", USER32_CreateWindowExA },
    { "EndDialog", USER32_EndDialog },
    { "OffsetRect", USER32_OffsetRect },
    { "ClientToScreen", USER32_ClientToScreen },
    { "GetSystemMetrics", USER32_GetSystemMetrics },
    { "SetCursor", USER32_SetCursor },
    { "DestroyWindow", USER32_DestroyWindow },
    { "ShowWindow", USER32_ShowWindow },
    { "SystemParametersInfoA", USER32_SystemParametersInfoA },
    { "GetClientRect", USER32_GetClientRect },
    { "RegisterClassA", USER32_RegisterClassA },
    { "MessageBoxA", USER32_MessageBoxA },
    { "DispatchMessageA", USER32_DispatchMessageA },
    { "DefWindowProcA", USER32_DefWindowProcA },
    { "PeekMessageA", USER32_PeekMessageA },
    { "DialogBoxIndirectParamA", USER32_DialogBoxIndirectParamA },
    { "SendDlgItemMessageA", USER32_SendDlgItemMessageA },
    { NULL, NULL }
};

// -----
// WINMM
// -----

API_CALLBACK uint32_t WINMM_timeGetTime(void)
{
    LOG_EMULATED();

    return SDL_GetTicks() * SPEEDUP_FACTOR;
}

static const SymbolTable WINMM_SYMBOLS[] = {
    { "timeGetTime", WINMM_timeGetTime },
    { NULL, NULL }
};

// -----
// DDRAW
// -----

typedef struct DDRAW_Surface_Object
{
    const void *vtable;

    bool is_primary;
    SDL_Renderer *renderer;
    SDL_Texture *texture;

    void *pixbuf;
    int pitch;
} DDRAW_Surface_Object;

API_CALLBACK uint32_t DDRAW_Surface_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);

    DDRAW_Surface_Object *surfaceobj = cominterface;
    if (!surfaceobj->is_primary) {
        SDL_DestroyTexture(surfaceobj->texture);
        SDL_DestroyRenderer(surfaceobj->renderer);
    }
    free(surfaceobj);

    return 0;
}

API_CALLBACK void *DDRAW_Surface_Blt(
    void *cominterface, void *UNUSED(rect1), void *UNUSED(surface),
    void *UNUSED(rect2), uint32_t UNUSED(flags), void *UNUSED(bltfx))
{
    LOG_EMULATED();
    assert(cominterface != NULL);
    return 0;
}

API_CALLBACK void *DDRAW_Surface_GetSurfaceDesc(void *cominterface, void *surface_desc)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(surface_desc != NULL);

    // Those are the values on my computer, I think it's safe to assume
    // nowaways we can always get RGBA8 anyway...
    // ddrawsurfacedesc->pixelformat->dwRGBBitCount
    *((uint32_t *)surface_desc+0x54/4) = 32;
    // ddrawsurfacedesc->pixelformat->dwRBitMask
    *((uint32_t *)surface_desc+0x58/4) = 0x00FF0000;
    // ddrawsurfacedesc->pixelformat->dwGBitMask
    *((uint32_t *)surface_desc+0x5C/4) = 0x0000FF00;

    return 0;
}

API_CALLBACK void *DDRAW_Surface_IsLost(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);

    return 0;
}

API_CALLBACK void *DDRAW_Surface_Restore(void *cominterface)
{
    // This is never called in practice since our IsLost does never return
    // true since there isn't a SDL equivalent
    LOG_EMULATED();

    assert(cominterface != NULL);

    return 0;
}

API_CALLBACK void *DDRAW_Surface_Lock(void *cominterface, void *rect, void *surface_desc, uint32_t flags, void *event)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(rect == NULL);
    assert(surface_desc != NULL);
    assert(flags == 1);
    assert(event == NULL);

    DDRAW_Surface_Object *surfaceobj = (DDRAW_Surface_Object *)cominterface;
    assert(!surfaceobj->is_primary);
    assert(surfaceobj->pixbuf == NULL);

    SDL_LockTexture(surfaceobj->texture, NULL, &surfaceobj->pixbuf, &surfaceobj->pitch);

    // pitch
    *((uint32_t *)surface_desc+0x10/4) = (uint32_t)surfaceobj->pitch;
    // Surface data pointer
    *((void **)surface_desc+0x24/4) = surfaceobj->pixbuf;

    return 0;
}

API_CALLBACK void *DDRAW_Surface_SetClipper(void *cominterface, void *clipper)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(clipper != NULL);

    return 0;
}

API_CALLBACK void *DDRAW_Surface_Unlock(void *cominterface, void *rect)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(rect != NULL);

    DDRAW_Surface_Object *surfaceobj = (DDRAW_Surface_Object *)cominterface;
    assert(!surfaceobj->is_primary);
    assert(surfaceobj->pixbuf != NULL);

    SDL_UnlockTexture(surfaceobj->texture);
    surfaceobj->pixbuf = NULL;

    SDL_RenderClear(surfaceobj->renderer);
    SDL_RenderCopy(surfaceobj->renderer, surfaceobj->texture, NULL, NULL);
    SDL_RenderPresent(surfaceobj->renderer);

    return  0;
}

static const void *DDRAW_Surface_VTABLE[256] = {
    [0x08/4] = DDRAW_Surface_Release,
    [0x14/4] = DDRAW_Surface_Blt,
    [0x58/4] = DDRAW_Surface_GetSurfaceDesc,
    [0x60/4] = DDRAW_Surface_IsLost,
    [0x64/4] = DDRAW_Surface_Lock,
    [0x6C/4] = DDRAW_Surface_Restore,
    [0x70/4] = DDRAW_Surface_SetClipper,
    [0x80/4] = DDRAW_Surface_Unlock,
};

API_CALLBACK uint32_t DDRAW_Clipper_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    return 0;
}

API_CALLBACK void *DDRAW_Clipper_SetHWnd(void *cominterface, uint32_t flags, void *hwnd)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(flags == 0);
    assert(hwnd != NULL);

    return 0;
}

static const void *DDRAW_Clipper_VTABLE[256] = {
    [0x08/4] = DDRAW_Clipper_Release,
    [0x20/4] = DDRAW_Clipper_SetHWnd,
};

typedef struct DDRAW_Clipper_Object
{
    const void *vtable;
} DDRAW_Clipper_Object;

typedef struct DDRAW_Object
{
    const void *vtable;
    SDL_Window *window;
} DDRAW_Object;

API_CALLBACK uint32_t DDRAW_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    free((DDRAW_Object *)cominterface);
    return 0;
}

API_CALLBACK void *DDRAW_CreateClipper(void *cominterface, uint32_t flags, void **clipper, void *outer)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(flags == 0);
    assert(clipper != NULL);
    assert(outer == 0);

    static DDRAW_Clipper_Object DDRAW_Clipper_NULLOBJECT = { DDRAW_Clipper_VTABLE };
    *clipper = &DDRAW_Clipper_NULLOBJECT;
    return 0;
}

API_CALLBACK void *DDRAW_CreateSurface(
    void *cominterface, void *surface_desc, void **surface, void *outer)
{
    assert(cominterface != NULL);
    assert(surface_desc != NULL);
    assert(surface != NULL);
    assert(outer == NULL);

    DDRAW_Object *ddraw = (DDRAW_Object *)cominterface;
    assert(ddraw->window != NULL);

    bool is_primary_surface = *(uint32_t *)((uint8_t *)surface_desc + 104) & DDSCAPS_PRIMARYSURFACE;
    uint32_t raw_height = *(uint32_t *)((uint8_t *)surface_desc + 8);
    uint32_t raw_width = *(uint32_t *)((uint8_t *)surface_desc + 12);
    assert(raw_height < INT_MAX && raw_width < INT_MAX);
    int height = (int)raw_height, width = (int)raw_width;

    DDRAW_Surface_Object *surfaceobj = malloc(sizeof(DDRAW_Surface_Object));
    surfaceobj->vtable = DDRAW_Surface_VTABLE;
    surfaceobj->is_primary = is_primary_surface;
    surfaceobj->renderer = NULL;
    surfaceobj->texture = NULL;
    surfaceobj->pixbuf = NULL;

    if (!is_primary_surface) {
        SDL_SetWindowSize(ddraw->window, width, height);

        surfaceobj->renderer = SDL_CreateRenderer(ddraw->window, -1, 0);
        if (surfaceobj->renderer == NULL) {
            fprintf(stderr, "Couldn't open SDL renderer: %s\n", SDL_GetError());
            exit(EXIT_FAILURE);
        }

        surfaceobj->texture = SDL_CreateTexture(surfaceobj->renderer, SDL_PIXELFORMAT_ARGB8888,
                                                SDL_TEXTUREACCESS_STREAMING, width, height);
        if (surfaceobj->texture == NULL) {
            fprintf(stderr, "Couldn't open SDL texture: %s\n", SDL_GetError());
            exit(EXIT_FAILURE);
        }
    }

    *surface = surfaceobj;
    return 0;
}

API_CALLBACK void *DDRAW_RestoreDisplayMode(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);

    return 0;
}

API_CALLBACK void *DDRAW_SetCooperativeLevel(
    void *cominterface, void *hwnd, uint32_t flags)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(hwnd != NULL);

    DDRAW_Object *ddraw = (DDRAW_Object *)cominterface;
    assert(ddraw->window == NULL);
    ddraw->window = (SDL_Window *)hwnd;

    if (flags & (DDSCL_FULLSCREEN | DDSCL_EXCLUSIVE)) {
        SDL_SetWindowFullscreen(ddraw->window, SDL_WINDOW_FULLSCREEN_DESKTOP);
    }

    return 0;
}

API_CALLBACK void *DDRAW_SetDisplayMode(void *cominterface,
    uint32_t UNUSED(width), uint32_t UNUSED(height), uint32_t bpp)
{
    LOG_EMULATED();
    assert(cominterface != NULL);
    assert(bpp == 32);
    return 0;
}

static const void *DDRAW_VTABLE[256] = {
    [0x08/4] = DDRAW_Release,
    [0x10/4] = DDRAW_CreateClipper,
    [0x18/4] = DDRAW_CreateSurface,
    [0x4C/4] = DDRAW_RestoreDisplayMode,
    [0x50/4] = DDRAW_SetCooperativeLevel,
    [0x54/4] = DDRAW_SetDisplayMode,
};

API_CALLBACK void *DDRAW_DirectDrawCreate(
    void *guid, void **lpdd, void *unkouter)
{
    LOG_EMULATED();

    assert(guid == NULL);
    assert(lpdd != NULL);
    assert(unkouter == NULL);

    DDRAW_Object *ddraw = malloc(sizeof(DDRAW_Object));
    ddraw->vtable = DDRAW_VTABLE;
    ddraw->window = NULL;
    *lpdd = ddraw;
    return 0;
}

static const SymbolTable DDRAW_SYMBOLS[] = {
    { "DirectDrawCreate", DDRAW_DirectDrawCreate },
    { NULL, NULL }
};

// -----
// SETUP
// -----

static const LibraryTable GLOBAL_LIBRARY_TABLE_TMP[] = {
    { "ddraw.dll", DDRAW_SYMBOLS },
    { "dsound.dll", DSOUND_SYMBOLS },
    { "kernel32.dll", KERNEL32_SYMBOLS },
    { "user32.dll", USER32_SYMBOLS },
    { "winmm.dll", WINMM_SYMBOLS },
    { NULL, NULL }
};

static const LibraryTable *GLOBAL_LIBRARY_TABLE = GLOBAL_LIBRARY_TABLE_TMP;

static int is_simple_command(const char *s) {
    for (size_t i = 0; i < strlen(s); i++)
        // List of characters from python's shlex.quote
        if (!strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-", s[i]))
            return false;
    return true;
}

// Converts a argc / argv pair to a single command line string,
// quoting arguments and escaping characters if necessary
// e.g. argv = ['./h7shim', 'w', 'the game', 'the ga"\me']
// -> './h7shim w "the game" "the ga\"\\me"'
// NOTE: This function is not bulletproof (e.g. UTF-8 support, )
static char *ArgvToCommandLine(int argc, char *argv[]) {
    size_t maxlen = 1;
    for (int argi = 0; argi < argc; argi++)
        maxlen += strlen(argv[argi]) * 2 + 3;

    char *command_line = malloc(maxlen);
    if (command_line == NULL)
        return NULL;

    char *cmdp = command_line;
    for (int argi = 0; argi < argc; argi++) {
        if (is_simple_command(argv[argi])) {
            strcpy(cmdp, argv[argi]);
            cmdp += strlen(argv[argi]);
        } else {
            *cmdp++ = '"';
            for (size_t i = 0; i < strlen(argv[argi]); i++) {
                if (argv[argi][i] == '"' || argv[argi][i] == '\\')
                    *cmdp++ = '\\';
                *cmdp++ = argv[argi][i];
            }
            *cmdp++ = '"';
        }

        if (argi != argc - 1)
            *cmdp++ = ' ';
    }
    *cmdp = '\0';
    return command_line;
}

static void free_command_line(void) {
    free(COMMANDLINE);
}

bool WinAPI2SDL_Init(int argc, char *argv[]) {
    COMMANDLINE = ArgvToCommandLine(argc, argv);
    if (COMMANDLINE == NULL) {
        fprintf(stderr, "ERROR: Failed to set up command line.\n");
        return false;
    }

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO) < 0) {
        fprintf(stderr, "WARNING: Failed to initialize SDL.\n");
        free(COMMANDLINE);
        return false;
    }

    return true;
}

void WinAPI2SDL_Quit() {
    free_command_line();
    SDL_Quit();
}
