#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <pthread.h>
#include <SDL.h>

#define IMAGEBASE 0x400000
#define IMAGESIZE 0x2E000
#define ENTRYPOINT 0x42C8A0

static const struct Resolution {
    int width;
    int height;
} RESOLUTION_DATA[4] = {
    { 320, 240 },
    { 512, 384 },
    { 640, 480 },
    { 800, 600 },
};

#define SETTING_RESOLUTION 3 // See above
#define SETTING_TRACER 0 // 0 = 1x1, 1 = 2x2, 2 = 4x4
#define SETTING_NOSOUND 0
#define SETTING_SOUND44KHZ 0
#define SETTING_FULLSCREEN 1 // 0 or 1
#define SETTING_NOTEXT 0 // 0 or 1
#define SETTING_LOOP 0 // 0 or 1

static bool dump_frames = false;
static bool dump_audio = true;
#define SPEEDUP_FACTOR 1

#ifdef __GNUC__
#define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#define UNUSED(x) UNUSED_ ## x
#endif

#if 0
#define LOG_EMULATED() printf("[!] %s EMULATED!\n", __func__)
#else
#define LOG_EMULATED() do { } while(0)
#endif

#define STUB() do { printf("[!] %s STUB!\n", __func__); raise(SIGSEGV); } while(0)

static uint8_t *memcontrolblock = NULL;
static uint32_t surfaceptr[0x1000000/4];
static uint32_t frame_counter = 0;

typedef struct SymbolTable
{
    const char *symbolName;
    void *symbol;
} SymbolTable;

typedef struct LibraryTable
{
    const char *libraryName;
    SymbolTable *symbolTable;
} LibraryTable;

#define MAKE_SYMBOL_ORDINAL(ord) ((char *)(uint32_t)(ord))

static LibraryTable *GLOBAL_LIBRARY_TABLE;

// Creates a BMP file containing a visual representation of the given cellular automaton state
static bool write_bmp(size_t sizex, size_t sizey, uint32_t *pixbuf, const char *output_file_path)
{
    SDL_Surface *surface = SDL_CreateRGBSurfaceWithFormatFrom(
        pixbuf, sizex, sizey, 32, sizex*4, SDL_PIXELFORMAT_RGB888);
    if (surface == NULL)
        return false;

    bool ret = SDL_SaveBMP(surface, output_file_path) == 0;
    SDL_FreeSurface(surface);
    return ret;
}

static uint64_t getTimeStampMs()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000 + tv.tv_usec / 1000) * SPEEDUP_FACTOR;
}

// ------
// DSOUND
// ------

typedef struct DSound_SoundBufferImpl_Object
{
    void *vtable;

    bool is_primary;
    uint8_t *audio_buffer;
    uint32_t audio_buffer_size;
    bool audio_playing;
    uint32_t audio_playpos;

    FILE *dumpfile;
} DSound_SoundBufferImpl_Object;

static __attribute__((stdcall)) void *DSOUND_SoundBufferImpl_GetStatus(void *cominterface, uint32_t *status)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(status != NULL);

    *status = 5; // DSBSTATUS_PLAYING | DSBSTATUS_LOOPING
    return 0;
}

static __attribute__((stdcall)) void DSOUND_SoundBufferImpl_Restore()
{
    STUB();
}

static __attribute__((stdcall)) void *DSOUND_SoundBufferImpl_Lock(
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

static __attribute__((stdcall)) void *DSOUND_SoundBufferImpl_Unlock(
    void *cominterface, void *pvAudioPtr1, uint32_t dwAudioBytes1,
    void *UNUSED(pvAudioPtr2), uint32_t UNUSED(dwAudioBytes2))
{
    LOG_EMULATED();
    assert(cominterface != NULL);
    SDL_UnlockAudio();
    DSound_SoundBufferImpl_Object *bufferobj = (DSound_SoundBufferImpl_Object *)cominterface;

    if (bufferobj->dumpfile) {
        if (fwrite(pvAudioPtr1, 1, dwAudioBytes1, bufferobj->dumpfile) != dwAudioBytes1) {
            fprintf(stderr, "WARNING: Could not write to dump audio file, result may be incomplete.\n");

        }
    }

    return NULL;
}

static __attribute__((stdcall)) void *DSOUND_SoundBufferImpl_SetFormat(void *cominterface, void *format)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(format != NULL);

    return 0;
}

static __attribute__((stdcall)) void *DSOUND_SoundBufferImpl_Play(
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

static __attribute__((stdcall)) void *DSOUND_SoundBufferImpl_GetCurrentPosition(
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

static __attribute__((stdcall)) void *DSOUND_SoundBufferImpl_Stop(void *cominterface)
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

static __attribute__((stdcall)) void *DSOUND_SoundBufferImpl_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    DSound_SoundBufferImpl_Object *bufferobj = (DSound_SoundBufferImpl_Object *)cominterface;
    if (!bufferobj->is_primary) {
        SDL_CloseAudio();

        if (bufferobj->dumpfile)
            fclose(bufferobj->dumpfile);
    }
    free(bufferobj->audio_buffer);
    free(bufferobj);

    return 0;
}

static void *DSound_SoundBufferImpl_VTABLE[256] = {
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

static __attribute__((stdcall)) void *DSOUND_CreateSoundBuffer(
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
    uint32_t freq = waveformatex != NULL ? *(uint32_t *)((uint8_t *)waveformatex + 4) : 0;

    DSound_SoundBufferImpl_Object *bufferobj = malloc(sizeof(DSound_SoundBufferImpl_Object));
    bufferobj->vtable = DSound_SoundBufferImpl_VTABLE;
    bufferobj->is_primary = is_primary_buffer;
    bufferobj->audio_buffer = !is_primary_buffer ? malloc(buffer_size) : NULL;
    bufferobj->audio_buffer_size = !is_primary_buffer ? buffer_size : 0;
    bufferobj->audio_playing = false;
    bufferobj->audio_playpos = 0;
    bufferobj->dumpfile = NULL;

    if (!bufferobj->is_primary) {
        SDL_AudioSpec wav_spec;
        SDL_memset(&wav_spec, 0, sizeof(wav_spec));
        wav_spec.freq = freq * SPEEDUP_FACTOR;
        wav_spec.format = AUDIO_S16;
        wav_spec.channels = 2;
        wav_spec.samples = 4096;
        wav_spec.callback = AudioCallback;
        wav_spec.userdata = bufferobj;

        if (SDL_OpenAudio(&wav_spec, NULL) < 0) {
            fprintf(stderr, "Couldn't open SDL audio: %s\n", SDL_GetError());
            exit(EXIT_FAILURE);
        }

        if (dump_audio) {
            bufferobj->dumpfile = fopen("/tmp/h7audio.raw", "wb");
            if (bufferobj->dumpfile == NULL) {
                fprintf(stderr, "WARNING: Couldn't open audio dump file\n");
                exit(EXIT_FAILURE);
            }
        }
    }

    *ppdsb = bufferobj;
    return 0;
}

static __attribute__((stdcall)) void *DSOUND_SetCooperativeLevel(
    void *cominterface, void *hwnd, uint32_t UNUSED(flags))
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(hwnd == (void *)12346);

    return 0;
}

static __attribute__((stdcall)) void *DSOUND_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    return 0;
}

static void *DSOUND_VTABLE[256] = {
    [0x0C/4] = DSOUND_CreateSoundBuffer,
    [0x18/4] = DSOUND_SetCooperativeLevel,
    [0x8/4] = DSOUND_Release,
};

static struct DSOUND_Object
{
    void *vtable;
} DSOUND_NULLOBJECT = { DSOUND_VTABLE };

static __attribute__((stdcall)) void *DSOUND_DirectSoundCreate(
   void *guid, void **lpds, void *unkouter)
{
    LOG_EMULATED();

    assert(guid == NULL);
    assert(lpds != NULL);
    assert(unkouter == NULL);

    *lpds = &DSOUND_NULLOBJECT;
    return 0;
}

static SymbolTable DSOUND_SYMBOLS[] = {
    { MAKE_SYMBOL_ORDINAL(0x0001), DSOUND_DirectSoundCreate },
    { NULL, NULL }
};

// --------
// KERNEL32
// --------

// **MEMORY**

static __attribute__((stdcall)) void *KERNEL32_GlobalAlloc(uint32_t flags, uint32_t memsize)
{
    LOG_EMULATED();

    assert(flags == 0);

    void *alloc_addr = malloc(memsize);

    if (memcontrolblock == NULL) {
        uintptr_t addr = (uintptr_t)alloc_addr;
        addr = (addr + 31) & ~31;
        memcontrolblock = (uint8_t *)addr;
    }

    return alloc_addr;
}

static __attribute__((stdcall)) void *KERNEL32_GlobalFree(void *ptr)
{
    LOG_EMULATED();
    free(ptr);
    return NULL;
}

// **THREADING**

static __attribute__((stdcall)) void *KERNEL32_CreateThread(
      void *UNUSED(lpThreadAttributes), uint32_t UNUSED(dwStackSize), void *lpStartAddress,
      void *lpParameter, uint32_t UNUSED(dwCreationFlags), uint32_t *UNUSED(lpThreadId)
)
{
    LOG_EMULATED();

    pthread_t *thread = malloc(sizeof(pthread_t));
    pthread_create(thread, NULL, lpStartAddress, lpParameter);
    return thread;
}

static __attribute__((stdcall)) uint32_t KERNEL32_SetThreadPriority(void *UNUSED(thread), int UNUSED(priority))
{
    LOG_EMULATED();

    return 1;
}

static __attribute__((stdcall)) uint32_t KERNEL32_TerminateThread(void *thread, uint32_t UNUSED(exitCode))
{
    LOG_EMULATED();

    pthread_t *rthread = (pthread_t *)thread;
    pthread_cancel(*rthread);
    pthread_join(*rthread, NULL);
    return 1;
}

static __attribute__((stdcall)) uint32_t KERNEL32_CloseHandle(void *object)
{
    LOG_EMULATED();

    pthread_t *thread = (pthread_t *)object;
    free(thread);

    return 1;
}

// **CRITICAL SECTION**

static __attribute__((stdcall)) void KERNEL32_InitializeCriticalSection(void *pcs)
{
    LOG_EMULATED();

    pthread_mutex_t *mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(mutex, NULL);
    *((pthread_mutex_t **)pcs) = mutex;
}

static __attribute__((stdcall)) void KERNEL32_EnterCriticalSection(void *pcs)
{
    LOG_EMULATED();

    pthread_mutex_t *mutex = *((pthread_mutex_t **)pcs);
    pthread_mutex_lock(mutex);
}

static __attribute__((stdcall)) void KERNEL32_LeaveCriticalSection(void *pcs)
{
    LOG_EMULATED();

    pthread_mutex_t *mutex = *((pthread_mutex_t **)pcs);
    pthread_mutex_unlock(mutex);
}

static __attribute__((stdcall)) void KERNEL32_DeleteCriticalSection(void *pcs)
{
    LOG_EMULATED();

    pthread_mutex_t *mutex = *((pthread_mutex_t **)pcs);
    pthread_mutex_destroy(mutex);
    free(mutex);
}

// **MISC**

static __attribute__((stdcall)) char *KERNEL32_GetCommandLineA()
{
    LOG_EMULATED();

    static char *COMMANDLINE = "C:\\HEAVEN7W.EXE";
    return COMMANDLINE;
}


static __attribute__((stdcall)) void *KERNEL32_GetModuleHandleA(const char *moduleName)
{
    LOG_EMULATED();

    assert(moduleName == NULL);
    return (void *)IMAGEBASE;
}


static __attribute__((stdcall)) void KERNEL32_ExitProcess(uint32_t exitcode)
{
    LOG_EMULATED();
    exit((int)exitcode);
}

static __attribute__((stdcall)) void KERNEL32_Sleep(uint32_t timems)
{
    LOG_EMULATED();

    struct timespec ts;
    ts.tv_sec = timems / 1000;
    ts.tv_nsec = (timems % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

static __attribute__((stdcall)) void *KERNEL32_LoadLibraryA(const char *libraryName)
{
    LOG_EMULATED();

    assert(libraryName != NULL);

    LibraryTable *found = NULL;
    for (LibraryTable *l = GLOBAL_LIBRARY_TABLE; l->libraryName != NULL; l++) {
        if (strcasecmp(l->libraryName, libraryName) == 0) {
            found = l;
            break;
        }
    }

    if (found == NULL) {
        fprintf(stderr, "WARNING: Library '%s' not found.\n", libraryName);
    }

    return found;
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

static __attribute__((stdcall)) void *KERNEL32_GetProcAddress(void *module, const char *procName)
{
    LOG_EMULATED();

    assert(module != NULL);
    assert(procName != NULL);

    LibraryTable *lib = (LibraryTable *)module;
    SymbolTable *found = NULL;

    for (SymbolTable *s = lib->symbolTable; s->symbolName != NULL; s++) {
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

static SymbolTable KERNEL32_SYMBOLS[] = {
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

static __attribute__((stdcall)) void *USER32_RegisterClassA(const void *wndClass)
{
    LOG_EMULATED();

    assert(wndClass != NULL);

    return (void *)12345;
}

static __attribute__((stdcall)) void *USER32_CreateWindowExA(
    uint32_t UNUSED(exStyle), const char *UNUSED(className), const char *UNUSED(windowName), uint32_t UNUSED(style),
    int UNUSED(x), int UNUSED(y), int UNUSED(width), int UNUSED(height),
    void *UNUSED(hwndParent), void *UNUSED(menu), void *UNUSED(instance), void *UNUSED(pparam))
{
    LOG_EMULATED();

    return (void *)12346;
}

static __attribute__((stdcall)) uint32_t USER32_ShowWindow(void *hwnd, uint32_t cmdshow)
{
    LOG_EMULATED();

    assert(hwnd == (void *)12346);
    assert(cmdshow == 1);
    return 0;
}

static __attribute__((stdcall)) void USER32_DispatchMessageA()
{
    STUB();
}

static __attribute__((stdcall)) void USER32_DefWindowProcA()
{
    STUB();
}

static __attribute__((stdcall)) uint32_t USER32_PeekMessageA(
      void *UNUSED(msg), void *UNUSED(hWnd),
      uint32_t UNUSED(msgFilterMin), uint32_t UNUSED(msgFilterMax),
      uint32_t UNUSED(removeMsg))
{
    LOG_EMULATED();
    // I think that just never returning any message should work,
    // the windowproc does basically nothing I think
    return 0;
}

static __attribute__((stdcall)) uint32_t USER32_DestroyWindow(void *hwnd)
{
    LOG_EMULATED();
    assert(hwnd == (void *)12346);
    return 1;
}

static __attribute__((stdcall)) uint32_t USER32_ClientToScreen(void *hwnd, void *point)
{
    LOG_EMULATED();

    assert(hwnd == (void *)12346);
    assert(point != NULL);

    return 1;
}

static __attribute__((stdcall)) uint32_t USER32_GetClientRect(void *hwnd, void *rect)
{
    LOG_EMULATED();

    assert(hwnd == (void *)12346);
    assert(rect != NULL);

    return 1;
}

// **DIALOG**

static __attribute__((stdcall)) uint32_t USER32_DialogBoxIndirectParamA(
    void *UNUSED(instance), void *UNUSED(dialogTemplate),
    void *UNUSED(hwndParent), void *UNUSED(dialogFunc), void *UNUSED(initParam))
{
    LOG_EMULATED();

    // Here we don't do the dialog for now, but instead we
    // do some high level emulation of it
    // NOTES:
    // EBP = Start of memory allocated by first GlobalAlloc
    // ControlId 0x3EB = Resolution combobox, index goes to EBP+0x10
    // ControlId 0x3EC = Tracer combobox, index goes to EBP+0x58
    // ControlId 0x3F1 = Sound combobox, EBP+0x14 = 0x0 44 Khz, 0x100 22 Khz, 0x1 No sound
    // ControlId 0x3EE = Windowed checkbox, _negated_ bool goes to EBP+0x150
    // ControlId 0x3ED = No text checkbox, bool goes to EBP+0x18
    // ControlId 0x3EF = Looping checkbox, bool goes to EBP+0x1C
    *(uint32_t *)(memcontrolblock+0x10) = SETTING_RESOLUTION;
    *(uint32_t *)(memcontrolblock+0x58) = SETTING_TRACER;
    *(uint32_t *)(memcontrolblock+0x14) = SETTING_NOSOUND | (SETTING_SOUND44KHZ << 8);
    *(uint32_t *)(memcontrolblock+0x150) = SETTING_FULLSCREEN;
    *(uint32_t *)(memcontrolblock+0x18) = SETTING_NOTEXT;
    *(uint32_t *)(memcontrolblock+0x1C) = SETTING_LOOP;

    return 1;
}

static __attribute__((stdcall)) void USER32_SendDlgItemMessageA()
{
    STUB();
}

static __attribute__((stdcall)) void USER32_EndDialog()
{
    STUB();
}

// **MISC**

static __attribute__((stdcall)) void USER32_MessageBoxA()
{
    STUB();
}

static __attribute__((stdcall)) uint32_t USER32_OffsetRect(void *rect, int UNUSED(dx), int UNUSED(dy))
{
    LOG_EMULATED();

    assert(rect != NULL);
    return 1;
}

static __attribute__((stdcall)) int USER32_GetSystemMetrics(int index)
{
    LOG_EMULATED();

    if (index == 0) // SM_CXSCREEN
        return 1920;
    else if (index == 1) // SM_CYSCREEN
        return 1080;
    else if (index == 4) // SM_CYSCAPTION
        return 19;
    else
        assert(0);
}

static __attribute__((stdcall)) uint32_t USER32_SystemParametersInfoA(
    uint32_t action, uint32_t wparam, void *pparam, uint32_t winini)
{
    LOG_EMULATED();

    assert(action == 5); // SPI_GETBORDER
    assert(wparam == 0);
    assert(pparam != NULL);
    assert(winini == 0);

    *(uint32_t *)pparam = 1;
    return 1;
}

static __attribute__((stdcall)) void *USER32_SetCursor(void *UNUSED(cursor))
{
    LOG_EMULATED();
    return NULL;
}

static SymbolTable USER32_SYMBOLS[] = {
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

static __attribute__((stdcall)) uint32_t WINMM_timeGetTime()
{
    LOG_EMULATED();

    return (uint32_t)getTimeStampMs();
}

static SymbolTable WINMM_SYMBOLS[] = {
    { "timeGetTime", WINMM_timeGetTime },
    { NULL, NULL }
};

// -----
// DDRAW
// -----

static __attribute__((stdcall)) uint32_t DDRAW_Surface_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    return 0;
}

static __attribute__((stdcall)) void *DDRAW_Surface_Blt(
    void *cominterface, void *UNUSED(rect1), void *UNUSED(surface),
    void *UNUSED(rect2), uint32_t UNUSED(flags), void *UNUSED(bltfx))
{
    LOG_EMULATED();
    assert(cominterface != NULL);
    return 0;
}
static __attribute__((stdcall)) void *DDRAW_Surface_GetSurfaceDesc(void *cominterface, void *surface_desc)
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
static __attribute__((stdcall)) void *DDRAW_Surface_IsLost(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);

    return 0;
}

static __attribute__((stdcall)) void *DDRAW_Surface_Lock(void *cominterface, void *rect, void *surface_desc, uint32_t flags, void *event)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(rect == NULL);
    assert(surface_desc != NULL);
    assert(flags == 1);
    assert(event == NULL);

    // pitch
    *((uint32_t *)surface_desc+0x10/4) = RESOLUTION_DATA[SETTING_RESOLUTION].width*4;
    // Surface data pointer
    *((void **)surface_desc+0x24/4) = surfaceptr;

    return 0;
}
static __attribute__((stdcall)) void DDRAW_Surface_Restore()
{
    STUB();
}
static __attribute__((stdcall)) void *DDRAW_Surface_SetClipper(void *cominterface, void *clipper)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(clipper != NULL);

    return 0;
}

static __attribute__((stdcall)) void *DDRAW_Surface_Unlock(void *cominterface, void *rect)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(rect != NULL);

    if (dump_frames) {
        char bmp_name[100];
        sprintf(bmp_name, "/tmp/h7screen_%06u.bmp", frame_counter);
        if (!write_bmp(RESOLUTION_DATA[SETTING_RESOLUTION].width, RESOLUTION_DATA[SETTING_RESOLUTION].height, surfaceptr, bmp_name)) {
            fprintf(stderr, "WARNING: Could not write to dump bitmap file, result may be incomplete.\n");
        }
        frame_counter++;
    }

    return  0;
}

static void *DDRAW_Surface_VTABLE[256] = {
    [0x08/4] = DDRAW_Surface_Release,
    [0x14/4] = DDRAW_Surface_Blt,
    [0x58/4] = DDRAW_Surface_GetSurfaceDesc,
    [0x60/4] = DDRAW_Surface_IsLost,
    [0x64/4] = DDRAW_Surface_Lock,
    [0x6C/4] = DDRAW_Surface_Restore,
    [0x70/4] = DDRAW_Surface_SetClipper,
    [0x80/4] = DDRAW_Surface_Unlock,
};

static struct DDRAW_Surface_Object
{
    void *vtable;
} DDRAW_Surface_NULLOBJECT = { DDRAW_Surface_VTABLE };


static __attribute__((stdcall)) uint32_t DDRAW_Clipper_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    return 0;
}
static __attribute__((stdcall)) void *DDRAW_Clipper_SetHWnd(void *cominterface, uint32_t flags, void *hwnd)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(flags == 0);
    assert(hwnd == (void *)12346);

    return 0;
}

static void *DDRAW_Clipper_VTABLE[256] = {
    [0x08/4] = DDRAW_Clipper_Release,
    [0x20/4] = DDRAW_Clipper_SetHWnd,
};

static struct DDRAW_Clipper_Object
{
    void *vtable;
} DDRAW_Clipper_NULLOBJECT = { DDRAW_Clipper_VTABLE };

static __attribute__((stdcall)) uint32_t DDRAW_Release(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    return 0;
}

static __attribute__((stdcall)) void *DDRAW_CreateClipper(void *cominterface, uint32_t flags, void **clipper, void *outer)
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(flags == 0);
    assert(clipper != NULL);
    assert(outer == 0);

    *clipper = &DDRAW_Clipper_NULLOBJECT;
    return 0;
}

static __attribute__((stdcall)) void *DDRAW_CreateSurface(
    void *cominterface, void *surface_desc, void **surface, void *outer)
{
    assert(cominterface != NULL);
    assert(surface_desc != NULL);
    assert(surface != NULL);
    assert(outer == NULL);

    *surface = &DDRAW_Surface_NULLOBJECT;
    return 0;
}
static __attribute__((stdcall)) void *DDRAW_RestoreDisplayMode(void *cominterface)
{
    LOG_EMULATED();

    assert(cominterface != NULL);

    return 0;
}

static __attribute__((stdcall)) void *DDRAW_SetCooperativeLevel(
    void *cominterface, void *hwnd, uint32_t UNUSED(flags))
{
    LOG_EMULATED();

    assert(cominterface != NULL);
    assert(hwnd == (void *)12346);

    return 0;
}

static __attribute__((stdcall)) void *DDRAW_SetDisplayMode(void *cominterface,
    uint32_t UNUSED(width), uint32_t UNUSED(height), uint32_t bpp)
{
    LOG_EMULATED();
    assert(cominterface != NULL);
    assert(bpp == 32);
    return 0;
}

static void *DDRAW_VTABLE[256] = {
    [0x08/4] = DDRAW_Release,
    [0x10/4] = DDRAW_CreateClipper,
    [0x18/4] = DDRAW_CreateSurface,
    [0x4C/4] = DDRAW_RestoreDisplayMode,
    [0x50/4] = DDRAW_SetCooperativeLevel,
    [0x54/4] = DDRAW_SetDisplayMode,
};

static struct DDRAW_Object
{
    void *vtable;
} DDRAW_NULLOBJECT = { DDRAW_VTABLE };

static __attribute__((stdcall)) void *DDRAW_DirectDrawCreate(
    void *guid, void **lpdd, void *unkouter)
{
    LOG_EMULATED();

    assert(guid == NULL);
    assert(lpdd != NULL);
    assert(unkouter == NULL);

    *lpdd = &DDRAW_NULLOBJECT;
    return 0;
}

static SymbolTable DDRAW_SYMBOLS[] = {
    { "DirectDrawCreate", DDRAW_DirectDrawCreate },
    { NULL, NULL }
};

// ------------------------
// SETUP & CALL ENTRY POINT
// ------------------------

static LibraryTable GLOBAL_LIBRARY_TABLE_TMP[] = {
    { "ddraw.dll", DDRAW_SYMBOLS },
    { "dsound.dll", DSOUND_SYMBOLS },
    { "kernel32.dll", KERNEL32_SYMBOLS },
    { "user32.dll", USER32_SYMBOLS },
    { "winmm.dll", WINMM_SYMBOLS },
    { NULL, NULL }
};

static LibraryTable *GLOBAL_LIBRARY_TABLE = GLOBAL_LIBRARY_TABLE_TMP;

typedef void (*entrypoint_t)();

int main(void) {
    if (SDL_Init(SDL_INIT_AUDIO) < 0)
            return EXIT_FAILURE;

    char *image = mmap((void *)IMAGEBASE, IMAGESIZE, PROT_READ | PROT_WRITE,
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
        return EXIT_FAILURE;
    }

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
