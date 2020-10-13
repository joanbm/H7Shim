#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <SDL.h>

#define IMAGEBASE 0x400000
#define IMAGESIZE 0x2B000
#define ENTRYPOINT 0x40168C

struct Resolution {
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

// Writes a little-endian 16-bit unsigned integer to the given file
static void fputleu16(FILE *f, uint16_t value)
{
    uint8_t buf[2];
    buf[0] = (uint8_t)value;
    buf[1] = (uint8_t)(value >> 8u);
    fwrite(buf, 1, 2, f);
}

// Writes a little-endian 32-bit unsigned integer to the given file
static void fputleu32(FILE *f, uint32_t value)
{
    uint8_t buf[4];
    buf[0] = (uint8_t)value;
    buf[1] = (uint8_t)(value >> 8u);
    buf[2] = (uint8_t)(value >> 16u);
    buf[3] = (uint8_t)(value >> 24u);
    fwrite(buf, 1, 4, f);
}

// Creates a BMP file containing a visual representation of the given cellular automaton state
static bool write_bmp(size_t sizex, size_t sizey, uint32_t *pixbuf, char *output_file_path)
{
    // Calculate bitmap dimensions
    uint32_t bitmap_header_size = 14;
    uint32_t dib_header_size = 40;
    uint32_t palette_size = 8;
    uint32_t bitmap_offset = bitmap_header_size + dib_header_size + palette_size;

    uint32_t bitmap_size = (uint32_t)(sizex*sizey*4);
    uint32_t total_size = bitmap_offset + bitmap_size;

    FILE *fp = fopen(output_file_path, "wb");
    if (fp == NULL) {
        printf("Could not open the output image file\n");
        return false;
    }

    // Bitmap header
    fprintf(fp, "BM"); // Magic number
    fputleu32(fp, total_size);
    fputleu16(fp, 0); // Reserved
    fputleu16(fp, 0); // Reserved
    fputleu32(fp, bitmap_offset);

    // DIB header
    fputleu32(fp, dib_header_size);
    fputleu32(fp, sizex);
    fputleu32(fp, -(uint32_t)sizey); // Negative to avoid upside-down image data
    fputleu16(fp, 1); // Number of color planes
    fputleu16(fp, 32); // Bits per pixel
    fputleu32(fp, 0); // Compression (=None)
    fputleu32(fp, bitmap_size);
    fputleu32(fp, 0); // Horizontal resolution (=None)
    fputleu32(fp, 0); // Vertical resolution (=None)
    fputleu32(fp, 0); // Number of palette colors (=None)
    fputleu32(fp, 0); // Important colors (=All)

    // Image data
    for (size_t i = 0; i < sizex*sizey; i++) {
        fputleu32(fp, pixbuf[i]);
    }

    bool ok = ferror(fp) == 0;
    ok &= fclose(fp) != EOF;

    if (!ok) {
        printf("Could not write the output image file\n");
        remove(output_file_path);
    }

    return ok;
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
            fprintf(stderr, "WARNING: Could not write to dump audio file, result may be incomplete.");

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


static __attribute__((stdcall)) void *KERNEL32_GetModuleHandleA(char *moduleName)
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

// ------
// USER32
// ------

// **WINDOW**

static __attribute__((stdcall)) void *USER32_RegisterClassA(const void *wndClass)
{
    LOG_EMULATED();

    assert(wndClass != 0);

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
    assert(pparam != 0);
    assert(winini == 0);

    *(uint32_t *)pparam = 1;
    return 1;
}

static __attribute__((stdcall)) void *USER32_SetCursor(void *UNUSED(cursor))
{
    LOG_EMULATED();
    return NULL;
}


// -----
// WINMM
// -----

static __attribute__((stdcall)) uint32_t WINMM_timeGetTime()
{
    LOG_EMULATED();

    return (uint32_t)getTimeStampMs();
}

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
            fprintf(stderr, "WARNING: Could not write to dump bitmap file, result may be incomplete.");
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
    assert(clipper != 0);
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

    FILE *h7exe = fopen("HEAVEN7W_C.EXE", "rb");
    if (h7exe == NULL) {
        fprintf(stderr, "ERROR: Failed to open HEAVEN7 executable.\n");
        return EXIT_FAILURE;
    }
    size_t r = fread(image, 1, IMAGESIZE, h7exe);
    if (r != IMAGESIZE) {
        fprintf(stderr, "ERROR: Failed to read HEAVEN7 executable image.\n");
        return EXIT_FAILURE;
    }

    *((void **)(image + 0xF000)) = DDRAW_DirectDrawCreate;
    *((void **)(image + 0xF008)) = DSOUND_DirectSoundCreate;
    *((void **)(image + 0xF010)) = KERNEL32_GetCommandLineA;
    *((void **)(image + 0xF014)) = KERNEL32_GlobalFree;
    *((void **)(image + 0xF018)) = KERNEL32_CreateThread;
    *((void **)(image + 0xF01C)) = KERNEL32_GetModuleHandleA;
    *((void **)(image + 0xF020)) = KERNEL32_LeaveCriticalSection;
    *((void **)(image + 0xF024)) = KERNEL32_ExitProcess;
    *((void **)(image + 0xF028)) = KERNEL32_InitializeCriticalSection;
    *((void **)(image + 0xF02C)) = KERNEL32_SetThreadPriority;
    *((void **)(image + 0xF030)) = KERNEL32_EnterCriticalSection;
    *((void **)(image + 0xF034)) = KERNEL32_CloseHandle;
    *((void **)(image + 0xF038)) = KERNEL32_DeleteCriticalSection;
    *((void **)(image + 0xF03C)) = KERNEL32_GlobalAlloc;
    *((void **)(image + 0xF040)) = KERNEL32_Sleep;
    *((void **)(image + 0xF044)) = KERNEL32_TerminateThread;
    *((void **)(image + 0xF04C)) = USER32_CreateWindowExA;
    *((void **)(image + 0xF050)) = USER32_EndDialog;
    *((void **)(image + 0xF054)) = USER32_OffsetRect;
    *((void **)(image + 0xF058)) = USER32_ClientToScreen;
    *((void **)(image + 0xF05C)) = USER32_GetSystemMetrics;
    *((void **)(image + 0xF060)) = USER32_SetCursor;
    *((void **)(image + 0xF064)) = USER32_DestroyWindow;
    *((void **)(image + 0xF068)) = USER32_ShowWindow;
    *((void **)(image + 0xF06C)) = USER32_SystemParametersInfoA;
    *((void **)(image + 0xF070)) = USER32_GetClientRect;
    *((void **)(image + 0xF074)) = USER32_RegisterClassA;
    *((void **)(image + 0xF078)) = USER32_MessageBoxA;
    *((void **)(image + 0xF07C)) = USER32_DispatchMessageA;
    *((void **)(image + 0xF080)) = USER32_DefWindowProcA;
    *((void **)(image + 0xF084)) = USER32_PeekMessageA;
    *((void **)(image + 0xF088)) = USER32_DialogBoxIndirectParamA;
    *((void **)(image + 0xF08C)) = USER32_SendDlgItemMessageA;
    *((void **)(image + 0xF094)) = WINMM_timeGetTime;

    if (mprotect(image, IMAGESIZE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        fprintf(stderr, "ERROR: Failed to change HEAVEN7 executable memory protection.\n");
    }

    ((entrypoint_t)ENTRYPOINT)();

    return EXIT_SUCCESS;
}
